package observer

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type RedisTracingHook struct{}

func NewRedisTracingHook() *RedisTracingHook {
	return &RedisTracingHook{}
}

func (h *RedisTracingHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *RedisTracingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		cmdName := strings.ToUpper(cmd.Name())

		var span trace.Span
		if Tracer != nil {
			ctx, span = Tracer.Start(ctx, "redis."+cmdName,
				trace.WithSpanKind(trace.SpanKindClient),
				trace.WithAttributes(
					attribute.String("db.system", "redis"),
					attribute.String("redis.command", cmdName),
				),
			)
			defer span.End()
		}

		start := time.Now()
		err := next(ctx, cmd)
		duration := time.Since(start).Seconds()

		if redisCmdDurationHist != nil {
			redisCmdDurationHist.Record(ctx, duration,
				metric.WithAttributes(attribute.String("redis.command", cmdName)),
			)
		}

		if span != nil {
			if err != nil && err != redis.Nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			} else {
				span.SetStatus(codes.Ok, "")
			}
		}

		return err
	}
}

func (h *RedisTracingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		var span trace.Span
		if Tracer != nil {
			ctx, span = Tracer.Start(ctx, "redis.pipeline",
				trace.WithSpanKind(trace.SpanKindClient),
				trace.WithAttributes(
					attribute.String("db.system", "redis"),
					attribute.Int("redis.commands_count", len(cmds)),
				),
			)
			defer span.End()
		}

		start := time.Now()
		err := next(ctx, cmds)
		duration := time.Since(start).Seconds()

		if redisCmdDurationHist != nil {
			redisCmdDurationHist.Record(ctx, duration,
				metric.WithAttributes(attribute.String("redis.command", "PIPELINE")),
			)
		}

		if span != nil {
			if err != nil && err != redis.Nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			} else {
				span.SetStatus(codes.Ok, "")
			}
		}

		return err
	}
}

