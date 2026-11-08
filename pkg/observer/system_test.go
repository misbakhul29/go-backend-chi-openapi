package observer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/misbakhul29/backend-framework/pkg/observer"
)

func TestCollectSystemDiagnostics(t *testing.T) {
	diag := observer.CollectSystemDiagnostics(context.Background(), nil, nil, nil)

	if diag.Status == "" {
		t.Error("expected non-empty status")
	}
	if diag.GoVersion == "" {
		t.Error("expected non-empty go_version")
	}
	if diag.CPU.NumCPU <= 0 {
		t.Errorf("expected NumCPU > 0, got %d", diag.CPU.NumCPU)
	}
	if diag.CPU.NumGoroutine <= 0 {
		t.Errorf("expected NumGoroutine > 0, got %d", diag.CPU.NumGoroutine)
	}
	if diag.Memory.AllocMB <= 0 {
		t.Errorf("expected AllocMB > 0, got %f", diag.Memory.AllocMB)
	}
}

func TestSystemDiagnosticsHandler(t *testing.T) {
	handler := observer.SystemDiagnosticsHandler(nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status/system", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// In the absence of DB, status is degraded so code is 503, but response JSON is valid
	body := rr.Body.String()
	if !strings.Contains(body, "alloc_mb") {
		t.Errorf("expected JSON to contain alloc_mb, got: %s", body)
	}
	if !strings.Contains(body, "num_goroutine") {
		t.Errorf("expected JSON to contain num_goroutine, got: %s", body)
	}
}

