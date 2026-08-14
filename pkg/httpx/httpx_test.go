package httpx_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/errs"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"message": "success"}

	httpx.WriteJSON(w, http.StatusOK, data)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
	}

	var res map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res["message"] != "success" {
		t.Errorf("expected 'success', got '%s'", res["message"])
	}
}

func TestWriteError_Sentinel(t *testing.T) {
	tests := []struct {
		err          error
		expectedCode int
		expectedMsg  string
		expectedErr  string
	}{
		{httpx.ErrNotFound, http.StatusNotFound, "NOT_FOUND", "Data tidak ditemukan"},
		{httpx.ErrValidation, http.StatusBadRequest, "VALIDATION_FAILED", "Validasi data gagal"},
		{httpx.ErrForbidden, http.StatusForbidden, "FORBIDDEN", "Anda tidak memiliki akses ke sumber daya ini"},
		{httpx.ErrConflict, http.StatusConflict, "CONFLICT", "Konflik akses data terdeteksi, silakan coba lagi"},
		{errors.New("unknown error"), http.StatusInternalServerError, "INTERNAL_ERROR", "Terjadi kesalahan internal, silakan coba lagi"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedMsg, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/?lang=id", nil)
			w := httptest.NewRecorder()

			// Add language to context
			ctx := errs.WithLanguage(r.Context(), errs.ID)
			r = r.WithContext(ctx)

			httpx.WriteError(w, r, tt.err)

			if w.Code != tt.expectedCode {
				t.Errorf("expected status %d, got %d", tt.expectedCode, w.Code)
			}

			var errResp httpx.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if errResp.Error.Code != tt.expectedMsg {
				t.Errorf("expected code %s, got %s", tt.expectedMsg, errResp.Error.Code)
			}

			if errResp.Error.Message != tt.expectedErr {
				t.Errorf("expected message '%s', got '%s'", tt.expectedErr, errResp.Error.Message)
			}
		})
	}
}

func TestWriteError_DBError(t *testing.T) {
	// A translated DBError
	dbErr := &db.DBError{
		Code:       "DUPLICATE",
		MessageKey: "users_email_key",
		Message:    "Email sudah terdaftar",
		HTTPStatus: http.StatusConflict,
	}

	r := httptest.NewRequest("GET", "/?lang=en", nil)
	w := httptest.NewRecorder()

	ctx := errs.WithLanguage(r.Context(), errs.EN)
	r = r.WithContext(ctx)

	httpx.WriteError(w, r, dbErr)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
	}

	var errResp httpx.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if errResp.Error.Code != "DUPLICATE" {
		t.Errorf("expected code 'DUPLICATE', got '%s'", errResp.Error.Code)
	}

	// Should be English translation
	expectedMsg := "Email address is already registered"
	if errResp.Error.Message != expectedMsg {
		t.Errorf("expected message '%s', got '%s'", expectedMsg, errResp.Error.Message)
	}
}

func TestNewRouter(t *testing.T) {
	router := httpx.NewRouter()
	if router == nil {
		t.Fatal("expected router to be initialized")
	}

	router.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		lang := errs.LanguageFromContext(r.Context())
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"lang": string(lang)})
	})

	// Test Language resolver middleware via request
	r := httptest.NewRequest("GET", "/test?lang=en", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var res map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res["lang"] != "en" {
		t.Errorf("expected lang 'en', got '%s'", res["lang"])
	}
}
