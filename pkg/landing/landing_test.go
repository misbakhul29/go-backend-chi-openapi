package landing_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/landing"
)

func TestLandingHandler(t *testing.T) {
	config.Cfg = &config.Env{
		APPName: "Test Framework",
		Port:    "9000",
	}

	handler := landing.Handler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", contentType)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Test Framework") {
		t.Errorf("expected body to contain 'Test Framework'")
	}
	if !strings.Contains(body, "9000") {
		t.Errorf("expected body to contain port '9000'")
	}
	if !strings.Contains(body, "/api/v1/docs") {
		t.Errorf("expected body to link to Swagger docs")
	}
	if !strings.Contains(body, "https://github.com/misbakhul29/go-backend-chi-openapi") {
		t.Errorf("expected body to contain GitHub repository URL")
	}
	if !strings.Contains(body, "Kelebihan Menggunakan Template Ini") {
		t.Errorf("expected body to contain Kelebihan section")
	}
	if !strings.Contains(body, "Dokumentasi Cara Penggunaan") {
		t.Errorf("expected body to contain Panduan section")
	}
}

