package observer

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"gorm.io/gorm"
)

var (
	Reg = prometheus.NewRegistry()

	metricsOnce sync.Once
	metricsErr  error

	meter               metric.Meter
	httpDurationHist    metric.Float64Histogram
	httpRequestsCounter metric.Int64Counter
	httpInFlightGauge   metric.Int64UpDownCounter

	dbQueryDurationHist    metric.Float64Histogram
	redisCmdDurationHist   metric.Float64Histogram
	rabbitPublishedCounter metric.Int64Counter
)

func init() {
	Reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	_ = InitMetrics("backend-framework")
}

func InitMetrics(serviceName string) error {
	metricsOnce.Do(func() {
		if serviceName == "" {
			serviceName = "backend-framework"
		}

		res, _ := resource.Merge(
			resource.Default(),
			resource.NewWithAttributes(
				"",
				attribute.String("service.name", serviceName),
			),
		)

		exporter, err := otelprom.New(otelprom.WithRegisterer(Reg))
		if err != nil {
			metricsErr = err
			return
		}

		meterProvider := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(exporter),
			sdkmetric.WithResource(res),
		)
		otel.SetMeterProvider(meterProvider)

		meter = meterProvider.Meter(serviceName)

		httpDurationHist, err = meter.Float64Histogram("http.server.request.duration",
			metric.WithDescription("Duration of HTTP server requests in seconds"),
			metric.WithUnit("s"),
			metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
		)
		if err != nil {
			metricsErr = err
			return
		}

		httpRequestsCounter, err = meter.Int64Counter("http.server.requests",
			metric.WithDescription("Total number of HTTP requests processed"),
			metric.WithUnit("{request}"),
		)
		if err != nil {
			metricsErr = err
			return
		}

		httpInFlightGauge, err = meter.Int64UpDownCounter("http.server.active_requests",
			metric.WithDescription("Number of active in-flight HTTP requests"),
			metric.WithUnit("{request}"),
		)
		if err != nil {
			metricsErr = err
			return
		}

		dbQueryDurationHist, err = meter.Float64Histogram("db.client.query.duration",
			metric.WithDescription("Duration of database queries in seconds"),
			metric.WithUnit("s"),
			metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
		)
		if err != nil {
			metricsErr = err
			return
		}

		redisCmdDurationHist, err = meter.Float64Histogram("redis.client.command.duration",
			metric.WithDescription("Duration of Redis commands in seconds"),
			metric.WithUnit("s"),
			metric.WithExplicitBucketBoundaries(0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
		)
		if err != nil {
			metricsErr = err
			return
		}

		rabbitPublishedCounter, err = meter.Int64Counter("rabbitmq.messages.published",
			metric.WithDescription("Total number of messages published to RabbitMQ"),
			metric.WithUnit("{message}"),
		)
		if err != nil {
			metricsErr = err
			return
		}
	})

	return metricsErr
}

func RegisterDBMetrics(dbInstance *gorm.DB) {
	if dbInstance == nil || meter == nil {
		return
	}
	sqlDB, err := dbInstance.DB()
	if err != nil {
		return
	}

	openGauge := mustInt64ObservableGauge(meter, "db.client.connections.open", "Number of established open connections")
	inUseGauge := mustInt64ObservableGauge(meter, "db.client.connections.in_use", "Number of connections currently in use")
	idleGauge := mustInt64ObservableGauge(meter, "db.client.connections.idle", "Number of idle connections")

	_, _ = meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		stats := sqlDB.Stats()
		o.ObserveInt64(openGauge, int64(stats.OpenConnections))
		o.ObserveInt64(inUseGauge, int64(stats.InUse))
		o.ObserveInt64(idleGauge, int64(stats.Idle))
		return nil
	}, openGauge, inUseGauge, idleGauge)
}

func mustInt64ObservableGauge(m metric.Meter, name, desc string) metric.Int64ObservableGauge {
	g, _ := m.Int64ObservableGauge(name, metric.WithDescription(desc), metric.WithUnit("{connection}"))
	return g
}

func RecordRabbitMQPublished(ctx context.Context, exchange string) {
	if rabbitPublishedCounter != nil {
		rabbitPublishedCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("messaging.destination", exchange)))
	}
}

func MetricsHandler() http.Handler {
	return promhttp.HandlerFor(Reg, promhttp.HandlerOpts{})
}

func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if httpInFlightGauge != nil {
			httpInFlightGauge.Add(r.Context(), 1)
			defer httpInFlightGauge.Add(r.Context(), -1)
		}

		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		duration := time.Since(start).Seconds()

		routePattern := r.URL.Path
		if routeCtx := chi.RouteContext(r.Context()); routeCtx != nil && routeCtx.RoutePattern() != "" {
			routePattern = routeCtx.RoutePattern()
		}

		attrs := []attribute.KeyValue{
			attribute.String("http.method", r.Method),
			attribute.String("http.route", routePattern),
			attribute.String("http.status_code", strconv.Itoa(ww.Status())),
		}

		if httpRequestsCounter != nil {
			httpRequestsCounter.Add(r.Context(), 1, metric.WithAttributes(attrs...))
		}
		if httpDurationHist != nil {
			httpDurationHist.Record(r.Context(), duration, metric.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.route", routePattern),
			))
		}
	})
}
