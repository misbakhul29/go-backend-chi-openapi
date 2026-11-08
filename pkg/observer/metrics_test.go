package observer_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/misbakhul29/backend-framework/pkg/observer"
)

func TestMetricsEndpoint(t *testing.T) {
	r := chi.NewRouter()
	r.Use(observer.MetricsMiddleware)
	r.Handle("/metrics", observer.MetricsHandler())
	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})

	// 1. Make a request to track metrics
	reqPing := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rrPing := httptest.NewRecorder()
	r.ServeHTTP(rrPing, reqPing)

	if rrPing.Code != http.StatusOK {
		t.Fatalf("expected /ping to return 200, got %d", rrPing.Code)
	}

	// 2. Query /metrics
	reqMetrics := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rrMetrics := httptest.NewRecorder()
	r.ServeHTTP(rrMetrics, reqMetrics)

	if rrMetrics.Code != http.StatusOK {
		t.Fatalf("expected /metrics to return 200, got %d", rrMetrics.Code)
	}

	body := rrMetrics.Body.String()
	if body == "" {
		t.Error("expected non-empty metrics output")
	}
}

func TestTracerMiddleware(t *testing.T) {
	_, err := observer.InitTracer("test-service")
	if err != nil {
		t.Fatalf("failed to init tracer: %v", err)
	}

	r := chi.NewRouter()
	r.Use(observer.TracerMiddleware)
	r.Get("/test-trace", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test-trace", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	traceHeader := rr.Header().Get("X-Trace-Id")
	if traceHeader == "" {
		t.Error("expected X-Trace-Id header in response")
	}
}

