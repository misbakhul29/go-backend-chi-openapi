package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	apiv1 "github.com/misbakhul29/backend-framework/api/openapi/v1/generated"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/security"
)

// TestAdversarial_RTR_ConcurrentSameToken stress-tests RefreshToken when multiple concurrent
// requests present the exact same refresh token at the same millisecond.
// CRITICAL INVARIANT: At most ONE caller may succeed. Under no circumstances may
// concurrent calls fork the token lineage or issue multiple valid active refresh tokens.
func TestAdversarial_RTR_ConcurrentSameToken(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "concurrent-rtr@example.com"
	pass := "Str0ng#Pass123"

	_, err := svc.Register(ctx, "Concurrent User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, loginTokens, err := svc.Login(ctx, email, pass)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	rawRT := loginTokens.RefreshToken

	const numGoroutines = 20
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

	type result struct {
		tokens *security.IssuedTokens
		err    error
	}
	results := make([]result, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startBarrier // Synchronize simultaneous execution
			toks, rErr := svc.RefreshToken(ctx, rawRT)
			results[idx] = result{tokens: toks, err: rErr}
		}(i)
	}

	// Release all goroutines simultaneously
	close(startBarrier)
	wg.Wait()

	var successCount int
	var reuseDetectedCount int
	var unauthorizedCount int
	var otherErrCount int

	for _, res := range results {
		if res.err == nil && res.tokens != nil {
			successCount++
		} else if errors.Is(res.err, httpx.ErrTokenReuseDetected) {
			reuseDetectedCount++
		} else if errors.Is(res.err, httpx.ErrUnauthorized) {
			unauthorizedCount++
		} else {
			otherErrCount++
		}
	}

	t.Logf("Concurrent RTR results (N=%d): successes=%d, reuseDetected=%d, unauthorized=%d, otherErrors=%d",
		numGoroutines, successCount, reuseDetectedCount, unauthorizedCount, otherErrCount)

	// INVARIANT 1: At most 1 call can succeed.
	if successCount > 1 {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: %d concurrent calls succeeded on the same refresh token! Lineage was forked!", successCount)
	}

	// INVARIANT 2: Check active tokens in DB for this session/family
	var activeTokens []models.RefreshToken
	if err := gdb.Where("session_id = ? AND is_revoked = ?", loginTokens.SessionID, false).Find(&activeTokens).Error; err != nil {
		t.Fatalf("failed querying active tokens: %v", err)
	}

	// If reuse detection was triggered by a subsequent goroutine racing with the first,
	// activeTokens could be 0 (all revoked). If exactly 1 succeeded and no reuse triggered, activeTokens == 1.
	if len(activeTokens) > 1 {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: found %d active refresh tokens in DB for the same session!", len(activeTokens))
	}
}

// TestAdversarial_RTR_TokenFamilyReuseCascadeHTTP verifies token family theft detection through
// the HTTP layer:
// 1. Legitimate user rotates RT1 -> RT2.
// 2. Attacker replays RT1.
// 3. HTTP status must be 401 with code TOKEN_REUSE_DETECTED.
// 4. All tokens in the family and the parent session must be revoked.
// 5. RT2 must immediately fail.
// 6. Access tokens associated with that session must be rejected by RequireAuth middleware.
func TestAdversarial_RTR_TokenFamilyReuseCascadeHTTP(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	handler := NewHandler(svc)

	jwtVerifier := security.NewJWTVerifier([]byte("super-secret-test-key-32bytes!!"))
	jwtService := security.NewJWTService(jwtVerifier)
	authMiddleware := security.RequireAuth(jwtService, gdb)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, authMiddleware)

	// Helper for POST requests
	postJSON := func(path string, body any, bearerToken ...string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		if len(bearerToken) > 0 && bearerToken[0] != "" {
			req.Header.Set("Authorization", "Bearer "+bearerToken[0])
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// Helper for GET requests
	getJSON := func(path string, bearerToken string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+bearerToken)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	// 1. Register and Login
	_ = postJSON("/auth/register", map[string]string{
		"name":     "Victim User",
		"email":    "victim-rtr@example.com",
		"password": "Str0ng#Pass123",
	})

	loginRec := postJSON("/auth/login", map[string]string{
		"email":    "victim-rtr@example.com",
		"password": "Str0ng#Pass123",
	})
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: %d, body: %s", loginRec.Code, loginRec.Body.String())
	}

	var loginResp apiv1.SuccessLoginResponse
	_ = json.NewDecoder(loginRec.Body).Decode(&loginResp)
	at1 := *loginResp.AccessToken
	rt1 := *loginResp.RefreshToken

	// Verify AT1 works on protected route
	sessRec1 := getJSON("/auth/sessions", at1)
	if sessRec1.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 with AT1, got: %d", sessRec1.Code)
	}

	// 2. Legitimate user rotates RT1 -> RT2
	refRec1 := postJSON("/auth/refresh", map[string]string{"refreshToken": rt1})
	if refRec1.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on first refresh, got: %d (%s)", refRec1.Code, refRec1.Body.String())
	}

	var refResp1 apiv1.SuccessRefreshResponse
	_ = json.NewDecoder(refRec1.Body).Decode(&refResp1)
	at2 := *refResp1.AccessToken
	rt2 := *refResp1.RefreshToken

	// 3. Adversary replays already-revoked RT1!
	replayRec := postJSON("/auth/refresh", map[string]string{"refreshToken": rt1})

	// Assert HTTP 401
	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("CRITICAL SECURITY VIOLATION: expected HTTP 401 on token replay, got: %d (%s)",
			replayRec.Code, replayRec.Body.String())
	}

	// Assert response body contains code TOKEN_REUSE_DETECTED
	rawBody := replayRec.Body.String()
	var errResp httpx.ErrorResponse
	if err := json.Unmarshal([]byte(rawBody), &errResp); err != nil {
		t.Fatalf("failed decoding error response: %v (raw: %s)", err, rawBody)
	}
	codeVal := errResp.Error.Code
	if codeVal != "TOKEN_REUSE_DETECTED" {
		t.Fatalf("expected error code %q, got: %q (full body: %s)", "TOKEN_REUSE_DETECTED", codeVal, rawBody)
	}

	// 4. Assert all tokens in the family are revoked in DB
	var rt1Record, rt2Record models.RefreshToken
	_ = gdb.First(&rt1Record, "token_hash = ?", security.HashToken(rt1))
	_ = gdb.First(&rt2Record, "token_hash = ?", security.HashToken(rt2))

	if !rt1Record.IsRevoked {
		t.Errorf("expected RT1 to be revoked")
	}
	if !rt2Record.IsRevoked {
		t.Errorf("CRITICAL SECURITY VIOLATION: expected RT2 to be revoked after reuse detection!")
	}

	// 5. Assert parent session is revoked in DB
	var session models.Session
	if err := gdb.First(&session, "id = ?", rt1Record.SessionID).Error; err != nil {
		t.Fatalf("failed querying session: %v", err)
	}
	if !session.IsRevoked {
		t.Fatalf("CRITICAL SECURITY VIOLATION: expected session %s to have is_revoked = true", session.ID)
	}

	// 6. Legitimate RT2 must now also be rejected
	refRec2 := postJSON("/auth/refresh", map[string]string{"refreshToken": rt2})
	if refRec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 on RT2 after family revocation, got: %d", refRec2.Code)
	}

	// 7. Existing Access Tokens AT1 and AT2 must be immediately rejected by RequireAuth
	sessRecAfter1 := getJSON("/auth/sessions", at1)
	if sessRecAfter1.Code != http.StatusUnauthorized {
		t.Fatalf("CRITICAL SECURITY VIOLATION: AT1 still accepted after session revocation! Status: %d", sessRecAfter1.Code)
	}

	sessRecAfter2 := getJSON("/auth/sessions", at2)
	if sessRecAfter2.Code != http.StatusUnauthorized {
		t.Fatalf("CRITICAL SECURITY VIOLATION: AT2 still accepted after session revocation! Status: %d", sessRecAfter2.Code)
	}
}

// TestAdversarial_RTR_EdgeCasesAndAnomalies tests pathological inputs against RefreshToken.
func TestAdversarial_RTR_EdgeCasesAndAnomalies(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	// 1. Empty string
	_, err := svc.RefreshToken(ctx, "")
	if !errors.Is(err, httpx.ErrValidation) {
		t.Errorf("expected ErrValidation on empty token, got: %v", err)
	}

	// 2. Non-existent random string
	_, err = svc.RefreshToken(ctx, "non-existent-token-string-xyz123")
	if !errors.Is(err, httpx.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized on random token, got: %v", err)
	}

	// 3. Huge payload (100KB) to test memory safety and hash stability
	hugeToken := strings.Repeat("A", 100*1024)
	_, err = svc.RefreshToken(ctx, hugeToken)
	if !errors.Is(err, httpx.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized on huge token, got: %v", err)
	}

	// 4. Binary junk with null bytes
	junkToken := "\x00\x01\x02\xff\xfe\x00\x00malicious-payload"
	_, err = svc.RefreshToken(ctx, junkToken)
	if !errors.Is(err, httpx.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized on binary junk token, got: %v", err)
	}

	// 5. Valid token whose user has been deactivated (is_active = false)
	email := "deactivated@example.com"
	pass := "Str0ng#Pass123"
	user, err := svc.Register(ctx, "Deactivated User", email, pass)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}
	_, tokens, err := svc.Login(ctx, email, pass)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Deactivate user in DB
	if err := gdb.Model(&models.User{}).Where("id = ?", user.ID).Update("is_active", false).Error; err != nil {
		t.Fatalf("failed deactivating user: %v", err)
	}

	// Attempting refresh should fail with ErrUnauthorized
	_, err = svc.RefreshToken(ctx, tokens.RefreshToken)
	if !errors.Is(err, httpx.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized when user is inactive, got: %v", err)
	}
}

// TestAdversarial_RTR_PlaintextStorageAudit confirms that plaintext refresh tokens
// are NEVER persisted in SQLite/Postgres.
func TestAdversarial_RTR_PlaintextStorageAudit(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "storage-audit@example.com"
	pass := "Str0ng#Pass123"
	_, _ = svc.Register(ctx, "Audit User", email, pass)
	_, tokens, _ := svc.Login(ctx, email, pass)

	rawRT1 := tokens.RefreshToken
	newTokens, _ := svc.RefreshToken(ctx, rawRT1)
	rawRT2 := newTokens.RefreshToken

	// Query raw rows from refresh_token table
	type rawTokenRow struct {
		ID        string
		TokenHash string
	}
	var rows []rawTokenRow
	if err := gdb.Raw("SELECT id, token_hash FROM refresh_token").Scan(&rows).Error; err != nil {
		t.Fatalf("failed scanning refresh_token rows: %v", err)
	}

	if len(rows) != 2 {
		t.Fatalf("expected 2 token rows, got %d", len(rows))
	}

	for _, r := range rows {
		// 1. Must be exact 64-char SHA-256 hex string
		if len(r.TokenHash) != 64 {
			t.Errorf("token_hash %q is not 64 chars", r.TokenHash)
		}
		// 2. Must not match raw token
		if r.TokenHash == rawRT1 || r.TokenHash == rawRT2 {
			t.Fatalf("CRITICAL SECURITY VIOLATION: plaintext refresh token stored in DB!")
		}
	}

	// Check session table: token must NOT contain plaintext
	type rawSessionRow struct {
		ID        string
		Token     string
		TokenHash string
	}
	var sRows []rawSessionRow
	if err := gdb.Raw("SELECT id, token, token_hash FROM session").Scan(&sRows).Error; err != nil {
		t.Fatalf("failed scanning session rows: %v", err)
	}

	for _, s := range sRows {
		if s.Token == rawRT1 || s.Token == rawRT2 {
			t.Fatalf("CRITICAL SECURITY VIOLATION: plaintext refresh token stored in session.token!")
		}
		if len(s.TokenHash) != 64 {
			t.Errorf("session.token_hash %q is not 64 chars", s.TokenHash)
		}
	}
}

// TestAdversarial_SessionRevocation_MiddlewareImmediateBlock tests that once a session is revoked
// (via direct RevokeSession, RevokeAllSessions, or DELETE /auth/sessions), any existing access tokens
// are instantly rejected by RequireAuth without waiting for JWT expiration.
func TestAdversarial_SessionRevocation_MiddlewareImmediateBlock(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	jwtVerifier := security.NewJWTVerifier([]byte("super-secret-test-key-32bytes!!"))
	jwtService := security.NewJWTService(jwtVerifier)
	authMiddleware := security.RequireAuth(jwtService, gdb)

	ctx := context.Background()
	email := "mw-block@example.com"
	pass := "Str0ng#Pass123"

	user, _ := svc.Register(ctx, "MW User", email, pass)

	// Session 1
	_, tok1, _ := svc.Login(ctx, email, pass)
	// Session 2
	_, tok2, _ := svc.Login(ctx, email, pass)

	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("access-granted"))
	})

	checkAccess := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/resource", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		authMiddleware(protectedHandler).ServeHTTP(rec, req)
		return rec.Code
	}

	// Before revocation, both access tokens are valid
	if code := checkAccess(tok1.AccessToken); code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for tok1, got: %d", code)
	}
	if code := checkAccess(tok2.AccessToken); code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for tok2, got: %d", code)
	}

	// 1. Revoke session 1 specifically
	if err := svc.RevokeSession(ctx, tok1.SessionID, user.ID); err != nil {
		t.Fatalf("failed revoking session 1: %v", err)
	}

	// Tok1 must be blocked immediately
	if code := checkAccess(tok1.AccessToken); code != http.StatusUnauthorized {
		t.Fatalf("CRITICAL SECURITY VIOLATION: expected HTTP 401 for revoked session 1, got: %d", code)
	}

	// Tok2 must still be active
	if code := checkAccess(tok2.AccessToken); code != http.StatusOK {
		t.Fatalf("expected tok2 to remain active, got: %d", code)
	}

	// 2. Revoke all remaining sessions with exclude_current = false
	_, err := svc.RevokeAllSessions(ctx, user.ID, "", false)
	if err != nil {
		t.Fatalf("failed revoking all sessions: %v", err)
	}

	// Tok2 must now also be blocked immediately
	if code := checkAccess(tok2.AccessToken); code != http.StatusUnauthorized {
		t.Fatalf("CRITICAL SECURITY VIOLATION: expected HTTP 401 for revoked session 2, got: %d", code)
	}
}
