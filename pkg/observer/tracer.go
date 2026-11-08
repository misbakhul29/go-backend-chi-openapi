package observer

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

var Tracer trace.Tracer

func InitTracer(serviceName string) (*sdktrace.TracerProvider, error) {
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	Tracer = tp.Tracer(serviceName)
	return tp, nil
}

func TracerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		var span trace.Span
		if Tracer != nil {
			ctx, span = Tracer.Start(ctx, r.Method+" "+r.URL.Path)
			defer span.End()
		}

		spanContext := trace.SpanFromContext(ctx).SpanContext()
		if spanContext.IsValid() {
			traceID := spanContext.TraceID().String()
			ctx = context.WithValue(ctx, TraceIDKey, traceID)
			w.Header().Set("X-Trace-Id", traceID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

