package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	apiv1 "github.com/misbakhul29/backend-framework/api/openapi/v1/generated"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/security"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"gorm.io/gorm"
)

// setupAdversarialTestRouter builds a full Chi router with AuthHandler and RequireAuth middleware.
func setupAdversarialTestRouter(t *testing.T) (*gorm.DB, *AuthServiceImpl, http.Handler, string) {
	t.Helper()
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	handler := NewHandler(svc)

	jwtSecret := "super-secret-test-key-32bytes!!"
	jwtVerifier := security.NewJWTVerifier([]byte(jwtSecret))
	jwtService := security.NewJWTService(jwtVerifier)
	authMiddleware := security.RequireAuth(jwtService, gdb)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, authMiddleware)

	return gdb, svc, r, jwtSecret
}

// 1. Timing Attack Mitigation
func TestAdversarial_TimingAttackMitigation(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	validEmail := "target-user@example.com"
	correctPass := "Str0ng#Pass123"
	wrongPass := "Invalid#Pass999"
	nonExistentEmail := "nonexistent-user-timing@example.com"

	_, err := svc.Register(ctx, "Target User", validEmail, correctPass)
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	// Warmup to avoid JIT / cold-start cache anomalies
	_, _, _ = svc.Login(ctx, nonExistentEmail, wrongPass)
	_ = security.ResetFailedAttempts(ctx, nil, nonExistentEmail)
	_, _, _ = svc.Login(ctx, validEmail, wrongPass)
	_ = security.ResetFailedAttempts(ctx, nil, validEmail)

	const iterations = 15
	var nonExistentDurations []time.Duration
	var validUserDurations []time.Duration

	// Measure non-existent email logins
	for i := 0; i < iterations; i++ {
		_ = security.ResetFailedAttempts(ctx, nil, nonExistentEmail)
		start := time.Now()
		_, _, err := svc.Login(ctx, nonExistentEmail, wrongPass)
		dur := time.Since(start)

		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("iteration %d: expected ErrInvalidCredentials, got: %v", i, err)
		}
		nonExistentDurations = append(nonExistentDurations, dur)
	}

	// Measure valid email with invalid password logins
	for i := 0; i < iterations; i++ {
		_ = security.ResetFailedAttempts(ctx, nil, validEmail)
		start := time.Now()
		_, _, err := svc.Login(ctx, validEmail, wrongPass)
		dur := time.Since(start)

		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("iteration %d: expected ErrInvalidCredentials, got: %v", i, err)
		}
		validUserDurations = append(validUserDurations, dur)
	}

	var sumNonExistent time.Duration
	for _, d := range nonExistentDurations {
		sumNonExistent += d
	}
	meanNonExistent := time.Duration(int64(sumNonExistent) / int64(iterations))

	var sumValid time.Duration
	for _, d := range validUserDurations {
		sumValid += d
	}
	meanValid := time.Duration(int64(sumValid) / int64(iterations))

	t.Logf("Timing Results over %d iterations:", iterations)
	t.Logf("  Non-existent user mean: %v", meanNonExistent)
	t.Logf("  Valid user (wrong pass) mean: %v", meanValid)

	// Empirical Check 1: Non-existent user must take substantial time (> 10ms)
	// Without DummyVerifyPassword, it would return in < 0.5ms.
	if meanNonExistent < 10*time.Millisecond {
		t.Fatalf("TIMING LEAK DETECTED: non-existent email login returned in %v (< 10ms), DummyVerifyPassword not executing Argon2id!", meanNonExistent)
	}

	// Empirical Check 2: Ratio of means must be statistically close (within 0.5x to 2.0x)
	ratio := float64(meanNonExistent) / float64(meanValid)
	t.Logf("  NonExistent/Valid Mean Ratio: %.3f", ratio)

	if ratio < 0.5 || ratio > 2.0 {
		t.Fatalf("TIMING DISCREPANCY: ratio between non-existent (%v) and valid (%v) is %.2f, expected statistically close execution time",
			meanNonExistent, meanValid, ratio)
	}
}

// 2. Brute-Force Lockout
func TestAdversarial_BruteForceLockout(t *testing.T) {
	_, svc, router, _ := setupAdversarialTestRouter(t)
	ctx := context.Background()

	email := "lockout-victim@example.com"
	correctPass := "Str0ng#Pass123"
	wrongPass := "Wrong#Password999"

	_, err := svc.Register(ctx, "Victim", email, correctPass)
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	// Ensure clean state
	_ = security.ResetFailedAttempts(ctx, nil, email)

	// Subtest 2.1: 5 failed consecutive attempts trigger lockout (HTTP 423)
	for i := 1; i <= 4; i++ {
		loginPayload, _ := json.Marshal(apiv1.LoginRequest{
			Email:    openapi_types.Email(email),
			Password: wrongPass,
		})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginPayload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected HTTP 401 Unauthorized, got: %d", i, rec.Code)
		}
	}

	// 5th failed attempt: Still returns 401
	loginPayload, _ := json.Marshal(apiv1.LoginRequest{
		Email:    openapi_types.Email(email),
		Password: wrongPass,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// 6th attempt (even with CORRECT password): MUST return HTTP 423 Account Locked
	validPayload, _ := json.Marshal(apiv1.LoginRequest{
		Email:    openapi_types.Email(email),
		Password: correctPass,
	})
	req6 := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(validPayload))
	req6.Header.Set("Content-Type", "application/json")
	rec6 := httptest.NewRecorder()
	router.ServeHTTP(rec6, req6)

	if rec6.Code != http.StatusLocked {
		t.Fatalf("expected HTTP 423 (StatusLocked) after 5 failed attempts, got: %d (body: %s)", rec6.Code, rec6.Body.String())
	}

	// Subtest 2.2: Verify lockout counter resets upon successful authentication
	// Reset the lockout explicitly
	_ = security.ResetFailedAttempts(ctx, nil, email)

	// Perform 3 failed attempts
	for i := 1; i <= 3; i++ {
		_, _, err := svc.Login(ctx, email, wrongPass)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failed attempt %d: expected ErrInvalidCredentials, got: %v", i, err)
		}
	}

	// Perform 1 SUCCESSFUL login -> this MUST clear the 3 previous failures
	user, tokens, err := svc.Login(ctx, email, correctPass)
	if err != nil || user == nil || tokens == nil {
		t.Fatalf("expected successful login, got: %v", err)
	}

	// Now perform 4 failed attempts. If counter did NOT reset, attempt 2 would be attempt 5 and lock out.
	for i := 1; i <= 4; i++ {
		_, _, err := svc.Login(ctx, email, wrongPass)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("post-success attempt %d: expected ErrInvalidCredentials (not locked), got: %v", i, err)
		}
	}

	// Ensure still NOT locked on 4th attempt
	lockRes, err := security.CheckLockout(ctx, nil, email)
	if err != nil || !lockRes.Allowed {
		t.Fatalf("account should NOT be locked after 4 failures post-reset")
	}

	// 5th failure now triggers lockout
	_, _, err = svc.Login(ctx, email, wrongPass)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("5th post-success attempt: expected ErrInvalidCredentials, got: %v", err)
	}

	// 6th attempt should now be locked
	_, _, err = svc.Login(ctx, email, correctPass)
	if !errors.Is(err, httpx.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked on 6th attempt after reset, got: %v", err)
	}
}

// 3. Forgot & Reset Password
func TestAdversarial_ForgotPassword_ResetPassword_Lifecycle(t *testing.T) {
	gdb, svc, router, _ := setupAdversarialTestRouter(t)
	ctx := context.Background()

	email := "alice-recovery@example.com"
	oldPass := "Str0ng#Initial123"
	newPass := "Str0ng#Updated456"

	user, err := svc.Register(ctx, "Alice Recovery", email, oldPass)
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	// Establish two active sessions before password reset
	_, t1, err := svc.Login(ctx, email, oldPass, ClientInfo{Device: "Laptop"})
	if err != nil {
		t.Fatalf("login 1 failed: %v", err)
	}
	_, t2, err := svc.Login(ctx, email, oldPass, ClientInfo{Device: "Phone"})
	if err != nil {
		t.Fatalf("login 2 failed: %v", err)
	}

	// Subtest 3.1: Anti-Enumeration Generic Response
	// Non-existent email
	nonExistentPayload, _ := json.Marshal(apiv1.ForgotPasswordRequest{
		Email: "ghost-does-not-exist@example.com",
	})
	reqGhost := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(nonExistentPayload))
	reqGhost.Header.Set("Content-Type", "application/json")
	recGhost := httptest.NewRecorder()
	router.ServeHTTP(recGhost, reqGhost)

	if recGhost.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for non-existent email, got: %d", recGhost.Code)
	}

	// Existent email
	existentPayload, _ := json.Marshal(apiv1.ForgotPasswordRequest{
		Email: openapi_types.Email(email),
	})
	reqExistent := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(existentPayload))
	reqExistent.Header.Set("Content-Type", "application/json")
	recExistent := httptest.NewRecorder()
	router.ServeHTTP(recExistent, reqExistent)

	if recExistent.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for existent email, got: %d", recExistent.Code)
	}

	// Both response bodies must be IDENTICAL (anti-enumeration)
	if recGhost.Body.String() != recExistent.Body.String() {
		t.Fatalf("ANTI-ENUMERATION LEAK: responses differ!\nGhost: %s\nExistent: %s", recGhost.Body.String(), recExistent.Body.String())
	}

	// Subtest 3.2: Verification Token Storage Discipline
	var v models.Verification
	if err := gdb.First(&v, "identifier = ?", user.ID).Error; err != nil {
		t.Fatalf("expected verification record in DB: %v", err)
	}
	// The stored value must be a 64-character SHA-256 hex digest, NOT a plaintext token
	if len(v.Value) != 64 {
		t.Fatalf("SECURITY VIOLATION: verification token not stored as 64-char SHA-256 hash, len=%d (%s)", len(v.Value), v.Value)
	}

	// Generate known raw token and insert custom verification for controlled testing
	rawToken, _ := security.GenerateOpaqueToken(32)
	rawTokenHash := security.HashToken(rawToken)
	now := time.Now()

	expiredTokenRecord := &models.Verification{
		ID:         "ver-expired-test",
		Identifier: user.ID,
		Value:      rawTokenHash,
		ExpiresAt:  now.Add(-10 * time.Minute), // Expired!
		CreatedAt:  &now,
		UpdatedAt:  &now,
	}
	_ = gdb.Create(expiredTokenRecord)

	// Subtest 3.3: Expired Token Rejection
	resetExpiredPayload, _ := json.Marshal(apiv1.ResetPasswordRequest{
		Token:       rawToken,
		NewPassword: newPass,
	})
	reqExpired := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(resetExpiredPayload))
	reqExpired.Header.Set("Content-Type", "application/json")
	recExpired := httptest.NewRecorder()
	router.ServeHTTP(recExpired, reqExpired)

	if recExpired.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 Bad Request on expired token reset, got: %d (%s)", recExpired.Code, recExpired.Body.String())
	}

	// Clean up expired record and insert active record
	_ = gdb.Delete(expiredTokenRecord)

	activeRawToken, _ := security.GenerateOpaqueToken(32)
	activeTokenHash := security.HashToken(activeRawToken)
	activeRecord := &models.Verification{
		ID:         "ver-active-test",
		Identifier: user.ID,
		Value:      activeTokenHash,
		ExpiresAt:  now.Add(15 * time.Minute),
		CreatedAt:  &now,
		UpdatedAt:  &now,
	}
	if err := gdb.Create(activeRecord).Error; err != nil {
		t.Fatalf("failed creating active verification record: %v", err)
	}

	// Subtest 3.4: Successful Reset Password
	resetValidPayload, _ := json.Marshal(apiv1.ResetPasswordRequest{
		Token:       activeRawToken,
		NewPassword: newPass,
	})
	reqValid := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(resetValidPayload))
	reqValid.Header.Set("Content-Type", "application/json")
	recValid := httptest.NewRecorder()
	router.ServeHTTP(recValid, reqValid)

	if recValid.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on valid reset password, got: %d (%s)", recValid.Code, recValid.Body.String())
	}

	// Subtest 3.5: Single-Use Invalidation / Replay Attack
	// Replaying the same token must fail
	reqReplay := httptest.NewRequest(http.MethodPost, "/auth/reset-password", bytes.NewReader(resetValidPayload))
	reqReplay.Header.Set("Content-Type", "application/json")
	recReplay := httptest.NewRecorder()
	router.ServeHTTP(recReplay, reqReplay)

	if recReplay.Code != http.StatusBadRequest {
		t.Fatalf("REPLAY ATTACK NOT BLOCKED: expected HTTP 400 on replayed token, got: %d (%s)", recReplay.Code, recReplay.Body.String())
	}

	// Subtest 3.6: Session Revocation Cascade on Reset
	// Verify both pre-reset sessions (t1 and t2) are marked is_revoked = true in DB
	var s1, s2 models.Session
	if err := gdb.First(&s1, "id = ?", t1.SessionID).Error; err != nil {
		t.Fatalf("failed querying session 1: %v", err)
	}
	if err := gdb.First(&s2, "id = ?", t2.SessionID).Error; err != nil {
		t.Fatalf("failed querying session 2: %v", err)
	}

	if !s1.IsRevoked || !s2.IsRevoked {
		t.Fatalf("SESSION REVOCATION FAILED: expected sessions s1 and s2 to be revoked after password reset (s1=%v, s2=%v)", s1.IsRevoked, s2.IsRevoked)
	}

	// Verify that access tokens from old sessions are rejected by RequireAuth middleware
	reqProtected := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	reqProtected.Header.Set("Authorization", "Bearer "+t1.AccessToken)
	recProtected := httptest.NewRecorder()
	router.ServeHTTP(recProtected, reqProtected)

	if recProtected.Code != http.StatusUnauthorized {
		t.Fatalf("OLD ACCESS TOKEN STILL VALID: expected HTTP 401 using token from revoked session, got: %d", recProtected.Code)
	}

	// Subtest 3.7: Old password fails, new password succeeds
	_, _, err = svc.Login(ctx, email, oldPass)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected old password to fail after reset, got: %v", err)
	}

	_, newTokens, err := svc.Login(ctx, email, newPass)
	if err != nil || newTokens == nil {
		t.Fatalf("expected new password to succeed after reset, got: %v", err)
	}
}

// 4. Session Tenant Isolation
func TestAdversarial_SessionTenantIsolation(t *testing.T) {
	gdb, svc, router, _ := setupAdversarialTestRouter(t)
	ctx := context.Background()

	// Register & Login User A
	userA, err := svc.Register(ctx, "User Alpha", "alpha@tenant.example", "Str0ng#Alpha123")
	if err != nil {
		t.Fatalf("failed registering User A: %v", err)
	}
	_, tokensA, err := svc.Login(ctx, "alpha@tenant.example", "Str0ng#Alpha123")
	if err != nil {
		t.Fatalf("failed login User A: %v", err)
	}

	// Register & Login User B
	userB, err := svc.Register(ctx, "User Beta", "beta@tenant.example", "Str0ng#Beta1234")
	if err != nil {
		t.Fatalf("failed registering User B: %v", err)
	}
	_, tokensB, err := svc.Login(ctx, "beta@tenant.example", "Str0ng#Beta1234")
	if err != nil {
		t.Fatalf("failed login User B: %v", err)
	}

	// Subtest 4.1: User A attempts to revoke User B's session via HTTP DELETE /auth/sessions/{id}
	reqCrossRevoke := httptest.NewRequest(http.MethodDelete, "/auth/sessions/"+tokensB.SessionID, nil)
	reqCrossRevoke.Header.Set("Authorization", "Bearer "+tokensA.AccessToken)
	recCrossRevoke := httptest.NewRecorder()
	router.ServeHTTP(recCrossRevoke, reqCrossRevoke)

	if recCrossRevoke.Code != http.StatusNotFound {
		t.Fatalf("CROSS-TENANT REVOCATION BREACH: expected HTTP 404 when User A revokes User B session, got: %d (%s)",
			recCrossRevoke.Code, recCrossRevoke.Body.String())
	}

	// Assert User B's session remains active in DB
	var sessB models.Session
	if err := gdb.First(&sessB, "id = ?", tokensB.SessionID).Error; err != nil {
		t.Fatalf("failed querying User B session: %v", err)
	}
	if sessB.IsRevoked {
		t.Fatalf("CROSS-TENANT LEAK: User B session was revoked by User A!")
	}

	// Subtest 4.2: User B can still access protected endpoints
	reqUserB := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	reqUserB.Header.Set("Authorization", "Bearer "+tokensB.AccessToken)
	recUserB := httptest.NewRecorder()
	router.ServeHTTP(recUserB, reqUserB)

	if recUserB.Code != http.StatusOK {
		t.Fatalf("expected User B session to remain completely valid, got: %d", recUserB.Code)
	}

	// Subtest 4.3: User A attempts bulk session wipe with User A token
	reqBulkWipe := httptest.NewRequest(http.MethodDelete, "/auth/sessions", nil)
	reqBulkWipe.Header.Set("Authorization", "Bearer "+tokensA.AccessToken)
	recBulkWipe := httptest.NewRecorder()
	router.ServeHTTP(recBulkWipe, reqBulkWipe)

	if recBulkWipe.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on User A bulk wipe, got: %d", recBulkWipe.Code)
	}

	// User A session should now be revoked
	var sessA models.Session
	_ = gdb.First(&sessA, "id = ?", tokensA.SessionID)
	if !sessA.IsRevoked {
		t.Fatalf("expected User A session to be revoked after bulk wipe")
	}

	// User B session MUST STILL be active!
	_ = gdb.First(&sessB, "id = ?", tokensB.SessionID)
	if sessB.IsRevoked {
		t.Fatalf("CRITICAL ISOLATION FAILURE: User A bulk wipe revoked User B session!")
	}

	// Verify User A ID and User B ID are distinct
	if userA.ID == userB.ID {
		t.Fatal("userA and userB have same ID")
	}
}

// 5. Bulk Session Revocation
func TestAdversarial_BulkSessionRevocation(t *testing.T) {
	gdb, svc, router, _ := setupAdversarialTestRouter(t)
	ctx := context.Background()

	email := "bulk-adversarial@example.com"
	pass := "Str0ng#Bulk123"

	user, err := svc.Register(ctx, "Bulk Tester", email, pass)
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	// Subtest 5.1: exclude_current=true preserves current session and revokes all others
	_, s1, err := svc.Login(ctx, email, pass, ClientInfo{Device: "Device 1"})
	if err != nil {
		t.Fatalf("login s1 failed: %v", err)
	}
	_, s2, err := svc.Login(ctx, email, pass, ClientInfo{Device: "Device 2"})
	if err != nil {
		t.Fatalf("login s2 failed: %v", err)
	}
	_, s3, err := svc.Login(ctx, email, pass, ClientInfo{Device: "Device 3"})
	if err != nil {
		t.Fatalf("login s3 failed: %v", err)
	}

	// Revoke all other sessions using s3's token with exclude_current=true
	reqExclude := httptest.NewRequest(http.MethodDelete, "/auth/sessions?exclude_current=true", nil)
	reqExclude.Header.Set("Authorization", "Bearer "+s3.AccessToken)
	recExclude := httptest.NewRecorder()
	router.ServeHTTP(recExclude, reqExclude)

	if recExclude.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on DELETE /auth/sessions?exclude_current=true, got: %d (%s)",
			recExclude.Code, recExclude.Body.String())
	}

	var respExclude apiv1.SuccessRevokeAllSessionsResponse
	if err := json.NewDecoder(recExclude.Body).Decode(&respExclude); err != nil {
		t.Fatalf("failed decoding bulk revoke response: %v", err)
	}
	if respExclude.RevokedCount == nil || *respExclude.RevokedCount != 2 {
		t.Fatalf("expected revoked_count = 2, got: %v", respExclude.RevokedCount)
	}

	// Verify DB state
	var dbS1, dbS2, dbS3 models.Session
	_ = gdb.First(&dbS1, "id = ?", s1.SessionID)
	_ = gdb.First(&dbS2, "id = ?", s2.SessionID)
	_ = gdb.First(&dbS3, "id = ?", s3.SessionID)

	if !dbS1.IsRevoked || !dbS2.IsRevoked {
		t.Fatalf("expected s1 and s2 to be revoked in DB (s1=%v, s2=%v)", dbS1.IsRevoked, dbS2.IsRevoked)
	}
	if dbS3.IsRevoked {
		t.Fatalf("expected current session s3 to REMAIN ACTIVE when exclude_current=true")
	}

	// Verify middleware behavior: s1 access token must be rejected, s3 access token must be accepted
	reqS1Protected := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	reqS1Protected.Header.Set("Authorization", "Bearer "+s1.AccessToken)
	recS1Protected := httptest.NewRecorder()
	router.ServeHTTP(recS1Protected, reqS1Protected)
	if recS1Protected.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 for revoked s1 token, got: %d", recS1Protected.Code)
	}

	reqS3Protected := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	reqS3Protected.Header.Set("Authorization", "Bearer "+s3.AccessToken)
	recS3Protected := httptest.NewRecorder()
	router.ServeHTTP(recS3Protected, reqS3Protected)
	if recS3Protected.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for current s3 token, got: %d", recS3Protected.Code)
	}

	// Subtest 5.2: exclude_current=false revokes ALL sessions including current
	reqAll := httptest.NewRequest(http.MethodDelete, "/auth/sessions?exclude_current=false", nil)
	reqAll.Header.Set("Authorization", "Bearer "+s3.AccessToken)
	recAll := httptest.NewRecorder()
	router.ServeHTTP(recAll, reqAll)

	if recAll.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on DELETE /auth/sessions?exclude_current=false, got: %d", recAll.Code)
	}

	var respAll apiv1.SuccessRevokeAllSessionsResponse
	_ = json.NewDecoder(recAll.Body).Decode(&respAll)
	if respAll.RevokedCount == nil || *respAll.RevokedCount != 1 {
		t.Fatalf("expected revoked_count = 1 (only s3 remained active), got: %v", respAll.RevokedCount)
	}

	_ = gdb.First(&dbS3, "id = ?", s3.SessionID)
	if !dbS3.IsRevoked {
		t.Fatalf("expected s3 to be revoked when exclude_current=false")
	}

	// Now s3 access token must also be rejected by middleware
	reqS3NowRevoked := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	reqS3NowRevoked.Header.Set("Authorization", "Bearer "+s3.AccessToken)
	recS3NowRevoked := httptest.NewRecorder()
	router.ServeHTTP(recS3NowRevoked, reqS3NowRevoked)
	if recS3NowRevoked.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 for s3 after full wipe, got: %d", recS3NowRevoked.Code)
	}

	// Ensure user ID remains valid
	_ = user.ID
}
