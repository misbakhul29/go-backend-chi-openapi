package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	apiv1 "github.com/misbakhul29/backend-framework/api/openapi/v1/generated"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/security"
)

func TestHTTP_RegisterAndLoginFlow(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	handler := NewHandler(svc)

	jwtVerifier := security.NewJWTVerifier([]byte("super-secret-test-key-32bytes!!"))
	jwtService := security.NewJWTService(jwtVerifier)
	authMiddleware := security.RequireAuth(jwtService, gdb)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, authMiddleware)

	// 1. Register
	regBody, _ := json.Marshal(map[string]string{
		"name":     "HTTP Test User",
		"email":    "httptest@example.com",
		"password": "Str0ng#Password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected HTTP 201 on register, got: %d (%s)", rec.Code, rec.Body.String())
	}

	// 2. Duplicate registration conflict
	reqDup := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(regBody))
	reqDup.Header.Set("Content-Type", "application/json")
	recDup := httptest.NewRecorder()
	r.ServeHTTP(recDup, reqDup)

	if recDup.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409 on duplicate register, got: %d", recDup.Code)
	}

	// 3. Login
	loginBody, _ := json.Marshal(map[string]string{
		"email":    "httptest@example.com",
		"password": "Str0ng#Password123",
	})
	reqLogin := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	r.ServeHTTP(recLogin, reqLogin)

	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on login, got: %d (%s)", recLogin.Code, recLogin.Body.String())
	}

	var loginResp apiv1.SuccessLoginResponse
	if err := json.NewDecoder(recLogin.Body).Decode(&loginResp); err != nil {
		t.Fatalf("failed decoding login response: %v", err)
	}
	if loginResp.AccessToken == nil || *loginResp.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if loginResp.RefreshToken == nil || *loginResp.RefreshToken == "" {
		t.Fatal("expected non-empty refresh token")
	}

	// 4. Refresh token via HTTP
	refreshBody, _ := json.Marshal(map[string]string{
		"refreshToken": *loginResp.RefreshToken,
	})
	reqRef := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader(refreshBody))
	reqRef.Header.Set("Content-Type", "application/json")
	recRef := httptest.NewRecorder()
	r.ServeHTTP(recRef, reqRef)

	if recRef.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on refresh, got: %d (%s)", recRef.Code, recRef.Body.String())
	}

	var refResp apiv1.SuccessRefreshResponse
	_ = json.NewDecoder(recRef.Body).Decode(&refResp)
	if refResp.AccessToken == nil || refResp.RefreshToken == nil {
		t.Fatal("expected valid refreshed token pair")
	}
}

func TestHTTP_ForgotPasswordAndResetFlow(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	handler := NewHandler(svc)

	jwtVerifier := security.NewJWTVerifier([]byte("super-secret-test-key-32bytes!!"))
	jwtService := security.NewJWTService(jwtVerifier)
	authMiddleware := security.RequireAuth(jwtService, gdb)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, authMiddleware)

	// 1. Forgot password for non-existent user (anti-enumeration generic 200)
	body, _ := json.Marshal(map[string]string{"email": "unknown@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on forgot-password, got: %d", rec.Code)
	}

	// 2. Register real user
	ctx := context.Background()
	user, err := svc.Register(ctx, "Forgot User", "forgotuser@example.com", "Str0ng#Pass123")
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	// 3. Forgot password for real user
	body2, _ := json.Marshal(map[string]string{"email": "forgotuser@example.com"})
	req2 := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on forgot-password for real user, got: %d", rec2.Code)
	}

	// Seed verification token for testing reset
	rawResetToken, _ := security.GenerateOpaqueToken(32)
	now := time.Now()
	v := &models.Verification{
		ID:         "reset-test-token-id",
		Identifier: user.ID,
		Value:      security.HashToken(rawResetToken),
		ExpiresAt:  now.Add(15 * time.Minute),
		CreatedAt:  &now,
		UpdatedAt:  &now,
	}
	_ = gdb.Create(v)

	// 4. Reset password via HTTP
	resetBody, _ := json.Marshal(map[string]string{
		"token":       rawResetToken,
		"newPassword": "Brand#NewPassword2026",
	})
	reqReset := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(resetBody))
	reqReset.Header.Set("Content-Type", "application/json")
	recReset := httptest.NewRecorder()
	r.ServeHTTP(recReset, reqReset)

	if recReset.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on reset-password, got: %d (%s)", recReset.Code, recReset.Body.String())
	}

	// 5. Login with new password works
	loginBody, _ := json.Marshal(map[string]string{
		"email":    "forgotuser@example.com",
		"password": "Brand#NewPassword2026",
	})
	reqL := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	reqL.Header.Set("Content-Type", "application/json")
	recL := httptest.NewRecorder()
	r.ServeHTTP(recL, reqL)

	if recL.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on login with new password, got: %d", recL.Code)
	}
}

func TestHTTP_ChangePasswordFlow(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	handler := NewHandler(svc)

	jwtVerifier := security.NewJWTVerifier([]byte("super-secret-test-key-32bytes!!"))
	jwtService := security.NewJWTService(jwtVerifier)
	authMiddleware := security.RequireAuth(jwtService, gdb)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, authMiddleware)

	ctx := context.Background()
	_, err := svc.Register(ctx, "CP User", "cpuser@example.com", "Str0ng#Pass123")
	if err != nil {
		t.Fatalf("failed register: %v", err)
	}
	_, tokens, err := svc.Login(ctx, "cpuser@example.com", "Str0ng#Pass123")
	if err != nil {
		t.Fatalf("failed login: %v", err)
	}

	// 1. Change password without bearer auth should return 401
	body, _ := json.Marshal(map[string]any{
		"oldPassword": "Str0ng#Pass123",
		"newPassword": "Str0ng#NewPass456",
	})
	reqUnauth := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(body))
	reqUnauth.Header.Set("Content-Type", "application/json")
	recUnauth := httptest.NewRecorder()
	r.ServeHTTP(recUnauth, reqUnauth)

	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 on unauthenticated change-password, got: %d", recUnauth.Code)
	}

	// 2. Change password with bearer auth
	reqAuth := httptest.NewRequest(http.MethodPost, "/auth/change-password", bytes.NewReader(body))
	reqAuth.Header.Set("Content-Type", "application/json")
	reqAuth.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	recAuth := httptest.NewRecorder()
	r.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on change-password, got: %d (%s)", recAuth.Code, recAuth.Body.String())
	}
}
