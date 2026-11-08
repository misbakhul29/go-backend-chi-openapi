package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/security"
)

func TestRTR_SuccessfulRotation(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "rtr-success@example.com"
	pass := "Str0ng#Pass123"

	_, err := svc.Register(ctx, "RTR User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, loginTokens, err := svc.Login(ctx, email, pass)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	rt1 := loginTokens.RefreshToken

	// Execute rotation
	newTokens, err := svc.RefreshToken(ctx, rt1)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	if newTokens.AccessToken == "" || newTokens.RefreshToken == "" {
		t.Fatal("expected non-empty tokens in refresh response")
	}
	if newTokens.RefreshToken == rt1 {
		t.Fatal("expected new refresh token to be different from old refresh token")
	}

	// Verify old token in DB is revoked and replaced
	oldHash := security.HashToken(rt1)
	var oldRecord models.RefreshToken
	if err := gdb.First(&oldRecord, "token_hash = ?", oldHash).Error; err != nil {
		t.Fatalf("failed querying old token: %v", err)
	}
	if !oldRecord.IsRevoked {
		t.Errorf("expected old token to be marked is_revoked = true")
	}
	if oldRecord.ReplacedByTokenID == nil || *oldRecord.ReplacedByTokenID == "" {
		t.Errorf("expected replaced_by_token_id to be populated")
	}

	// Verify new token in DB is active and shares the same family_id
	newHash := security.HashToken(newTokens.RefreshToken)
	var newRecord models.RefreshToken
	if err := gdb.First(&newRecord, "token_hash = ?", newHash).Error; err != nil {
		t.Fatalf("failed querying new token: %v", err)
	}
	if newRecord.IsRevoked {
		t.Errorf("expected new token to have is_revoked = false")
	}
	if newRecord.FamilyID != oldRecord.FamilyID {
		t.Errorf("expected new token family_id %q to match old token family_id %q", newRecord.FamilyID, oldRecord.FamilyID)
	}
	if newRecord.ID != *oldRecord.ReplacedByTokenID {
		t.Errorf("expected old token replaced_by to match new token ID")
	}
}

func TestRTR_ChainedConsecutiveRotations(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "rtr-chain@example.com"
	pass := "Str0ng#Pass123"

	_, err := svc.Register(ctx, "Chain User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, loginTokens, err := svc.Login(ctx, email, pass)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	rt1 := loginTokens.RefreshToken

	// RT1 -> RT2
	t2, err := svc.RefreshToken(ctx, rt1)
	if err != nil {
		t.Fatalf("rotation 1 failed: %v", err)
	}
	rt2 := t2.RefreshToken

	// RT2 -> RT3
	t3, err := svc.RefreshToken(ctx, rt2)
	if err != nil {
		t.Fatalf("rotation 2 failed: %v", err)
	}
	rt3 := t3.RefreshToken

	// Verify family lineage across all three tokens
	var r1, r2, r3 models.RefreshToken
	_ = gdb.First(&r1, "token_hash = ?", security.HashToken(rt1))
	_ = gdb.First(&r2, "token_hash = ?", security.HashToken(rt2))
	_ = gdb.First(&r3, "token_hash = ?", security.HashToken(rt3))

	if r1.FamilyID != r2.FamilyID || r2.FamilyID != r3.FamilyID {
		t.Errorf("all 3 tokens must share identical family_id: %s, %s, %s", r1.FamilyID, r2.FamilyID, r3.FamilyID)
	}

	if !r1.IsRevoked || !r2.IsRevoked {
		t.Errorf("r1 and r2 must be revoked")
	}
	if r3.IsRevoked {
		t.Errorf("r3 must be active")
	}

	if r1.ReplacedByTokenID == nil || *r1.ReplacedByTokenID != r2.ID {
		t.Errorf("r1.ReplacedByTokenID should point to r2.ID")
	}
	if r2.ReplacedByTokenID == nil || *r2.ReplacedByTokenID != r3.ID {
		t.Errorf("r2.ReplacedByTokenID should point to r3.ID")
	}
}

func TestRTR_ReuseTheftDetection(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "rtr-theft@example.com"
	pass := "Str0ng#Pass123"

	_, err := svc.Register(ctx, "Theft Victim", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, loginTokens, err := svc.Login(ctx, email, pass)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	rt1 := loginTokens.RefreshToken

	// Normal user rotates RT1 -> RT2
	t2, err := svc.RefreshToken(ctx, rt1)
	if err != nil {
		t.Fatalf("rotation 1 failed: %v", err)
	}
	rt2 := t2.RefreshToken

	// Attacker now attempts to reuse the already-revoked RT1!
	_, err = svc.RefreshToken(ctx, rt1)
	if !errors.Is(err, httpx.ErrTokenReuseDetected) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: expected ErrTokenReuseDetected on reuse, got: %v", err)
	}

	// Verify all tokens in that family are now revoked
	var r1, r2 models.RefreshToken
	_ = gdb.First(&r1, "token_hash = ?", security.HashToken(rt1))
	_ = gdb.First(&r2, "token_hash = ?", security.HashToken(rt2))

	if !r1.IsRevoked || !r2.IsRevoked {
		t.Errorf("expected all tokens in family to be revoked after reuse detection")
	}

	// Verify parent session is marked revoked
	var session models.Session
	if err := gdb.First(&session, "id = ?", r1.SessionID).Error; err != nil {
		t.Fatalf("failed querying session: %v", err)
	}
	if !session.IsRevoked {
		t.Errorf("expected parent session to be marked is_revoked = true after reuse detection")
	}

	// Subsequent attempt with legitimate RT2 should also now fail with 401
	_, err = svc.RefreshToken(ctx, rt2)
	if err == nil {
		t.Fatalf("expected subsequent refresh with RT2 to fail after family revocation")
	}
}

func TestRTR_SessionRevocationBlocksMiddleware(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "rtr-mw@example.com"
	pass := "Str0ng#Pass123"

	_, err := svc.Register(ctx, "MW User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, loginTokens, err := svc.Login(ctx, email, pass)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	jwtVerifier := security.NewJWTVerifier([]byte("super-secret-test-key-32bytes!!"))
	jwtService := security.NewJWTService(jwtVerifier)
	authMiddleware := security.RequireAuth(jwtService, gdb)

	dummyProtectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// 1. Valid request before revocation: HTTP 200
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+loginTokens.AccessToken)
	rec := httptest.NewRecorder()
	authMiddleware(dummyProtectedHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 before revocation, got: %d", rec.Code)
	}

	// 2. Trigger reuse theft to revoke the session
	_, _ = svc.RefreshToken(ctx, loginTokens.RefreshToken) // RT1 -> RT2
	_, _ = svc.RefreshToken(ctx, loginTokens.RefreshToken) // Replay RT1 -> triggers reuse revocation

	// 3. Request with original access token must now immediately fail with HTTP 401
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.Header.Set("Authorization", "Bearer "+loginTokens.AccessToken)
	rec2 := httptest.NewRecorder()
	authMiddleware(dummyProtectedHandler).ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("CRITICAL SECURITY VIOLATION: expected HTTP 401 after session revocation, got: %d", rec2.Code)
	}
}

func TestRTR_NonExistentToken(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	randomToken, _ := security.GenerateOpaqueToken(32)
	_, err := svc.RefreshToken(ctx, randomToken)
	if !errors.Is(err, httpx.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for non-existent refresh token, got: %v", err)
	}
}

func TestRTR_ExpiredToken(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "rtr-expired@example.com"
	pass := "Str0ng#Pass123"

	user, err := svc.Register(ctx, "Expired User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	sessionID := uuid.NewString()
	familyID := uuid.NewString()
	rawToken, _ := security.GenerateOpaqueToken(32)
	tokenHash := security.HashToken(rawToken)

	past := time.Now().Add(-2 * time.Hour)
	session := &models.Session{
		ID:        sessionID,
		UserID:    user.ID,
		FamilyID:  familyID,
		TokenHash: tokenHash,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: past,
		UpdatedAt: past,
	}
	_ = gdb.Create(session)

	expiredToken := &models.RefreshToken{
		ID:        uuid.NewString(),
		SessionID: sessionID,
		FamilyID:  familyID,
		TokenHash: tokenHash,
		IsRevoked: false,
		ExpiresAt: past, // Expired!
		CreatedAt: past,
	}
	_ = gdb.Create(expiredToken)

	_, err = svc.RefreshToken(ctx, rawToken)
	if !errors.Is(err, httpx.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized on expired token, got: %v", err)
	}
}

func TestRTR_RevokedParentSession(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "rtr-revoked-sess@example.com"
	pass := "Str0ng#Pass123"

	user, err := svc.Register(ctx, "Revoked Sess User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	sessionID := uuid.NewString()
	familyID := uuid.NewString()
	rawToken, _ := security.GenerateOpaqueToken(32)
	tokenHash := security.HashToken(rawToken)

	now := time.Now()
	session := &models.Session{
		ID:        sessionID,
		UserID:    user.ID,
		FamilyID:  familyID,
		TokenHash: tokenHash,
		IsRevoked: true, // Parent session revoked
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = gdb.Create(session)

	tokenRecord := &models.RefreshToken{
		ID:        uuid.NewString(),
		SessionID: sessionID,
		FamilyID:  familyID,
		TokenHash: tokenHash,
		IsRevoked: false,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	_ = gdb.Create(tokenRecord)

	_, err = svc.RefreshToken(ctx, rawToken)
	if !errors.Is(err, httpx.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized when parent session is revoked, got: %v", err)
	}
}

func TestRTR_StorageSecurityHashOnly(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "rtr-hashonly@example.com"
	pass := "Str0ng#Pass123"

	_, err := svc.Register(ctx, "HashOnly User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, loginTokens, err := svc.Login(ctx, email, pass)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	rawToken := loginTokens.RefreshToken
	expectedHash := security.HashToken(rawToken)

	// Check refresh_token table
	var rt models.RefreshToken
	if err := gdb.First(&rt, "session_id = ?", loginTokens.SessionID).Error; err != nil {
		t.Fatalf("failed querying refresh token: %v", err)
	}

	if rt.TokenHash != expectedHash {
		t.Errorf("expected refresh_token.token_hash to be SHA-256 hash %q, got: %q", expectedHash, rt.TokenHash)
	}

	// Verify 64 character hex string
	if len(rt.TokenHash) != 64 {
		t.Errorf("expected 64 char hex hash, got len %d", len(rt.TokenHash))
	}

	// Raw token must NOT equal the stored hash
	if rt.TokenHash == rawToken {
		t.Fatalf("SECURITY VIOLATION: raw refresh token stored plaintext in database!")
	}
}
