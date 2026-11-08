package observer

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

var (
	Tracer     trace.Tracer
	Propagator = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
)

func InitTracer(serviceName string) (*sdktrace.TracerProvider, error) {
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

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(Propagator)
	Tracer = tp.Tracer(serviceName)
	return tp, nil
}

// TracerMiddleware starts an OpenTelemetry server span for each incoming HTTP request.
func TracerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := Propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		spanName := r.Method + " " + r.URL.Path
		if routeCtx := chi.RouteContext(r.Context()); routeCtx != nil && routeCtx.RoutePattern() != "" {
			spanName = r.Method + " " + routeCtx.RoutePattern()
		}

		var span trace.Span
		if Tracer != nil {
			ctx, span = Tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.method", r.Method),
					attribute.String("http.target", r.URL.Path),
					attribute.String("http.user_agent", r.UserAgent()),
					attribute.String("http.client_ip", r.RemoteAddr),
				),
			)
			defer span.End()
		}

		spanContext := trace.SpanFromContext(ctx).SpanContext()
		if spanContext.IsValid() {
			traceID := spanContext.TraceID().String()
			ctx = context.WithValue(ctx, TraceIDKey, traceID)
			w.Header().Set("X-Trace-Id", traceID)
		}

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r.WithContext(ctx))

		if span != nil {
			status := ww.Status()
			span.SetAttributes(attribute.Int("http.status_code", status))
			if status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(status))
			} else {
				span.SetStatus(codes.Ok, "")
			}
		}
	})
}
