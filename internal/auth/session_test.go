package auth

import (
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
)

func TestSession_CreateOnLogin(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "session-create@example.com"
	pass := "Str0ng#Pass123"

	user, err := svc.Register(ctx, "Session User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	clientInfo := ClientInfo{
		IPAddress: "203.0.113.195",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Device:    "Chrome on macOS",
	}

	_, tokens, err := svc.Login(ctx, email, pass, clientInfo)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Verify session in DB
	var sess models.Session
	if err := gdb.First(&sess, "id = ?", tokens.SessionID).Error; err != nil {
		t.Fatalf("failed querying session: %v", err)
	}

	if sess.UserID != user.ID {
		t.Errorf("expected session user_id %s, got %s", user.ID, sess.UserID)
	}
	if sess.IPAddress == nil || *sess.IPAddress != clientInfo.IPAddress {
		t.Errorf("expected IP %s, got %v", clientInfo.IPAddress, sess.IPAddress)
	}
	if sess.UserAgent == nil || *sess.UserAgent != clientInfo.UserAgent {
		t.Errorf("expected UA %s, got %v", clientInfo.UserAgent, sess.UserAgent)
	}
	if sess.Device == nil || *sess.Device != clientInfo.Device {
		t.Errorf("expected device %s, got %v", clientInfo.Device, sess.Device)
	}
	if sess.LastActiveAt == nil {
		t.Errorf("expected last_active_at to be non-nil")
	}
	if sess.FamilyID == "" {
		t.Errorf("expected non-empty family_id")
	}

	// Verify linked refresh token
	var rt models.RefreshToken
	if err := gdb.First(&rt, "session_id = ?", tokens.SessionID).Error; err != nil {
		t.Fatalf("failed querying refresh token: %v", err)
	}
	if rt.FamilyID != sess.FamilyID {
		t.Errorf("expected refresh token family_id to match session family_id")
	}
	if rt.TokenHash != sess.TokenHash {
		t.Errorf("expected refresh token hash to match session token hash")
	}
}

func TestSession_ListActiveSessions(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "session-list@example.com"
	pass := "Str0ng#Pass123"

	user, err := svc.Register(ctx, "List User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	// Login 3 times to create 3 sessions
	_, t1, err := svc.Login(ctx, email, pass, ClientInfo{Device: "Device 1"})
	if err != nil {
		t.Fatalf("login 1 failed: %v", err)
	}
	_, t2, err := svc.Login(ctx, email, pass, ClientInfo{Device: "Device 2"})
	if err != nil {
		t.Fatalf("login 2 failed: %v", err)
	}
	_, t3, err := svc.Login(ctx, email, pass, ClientInfo{Device: "Device 3"})
	if err != nil {
		t.Fatalf("login 3 failed: %v", err)
	}

	// Mark session 1 as revoked
	_ = gdb.Model(&models.Session{}).Where("id = ?", t1.SessionID).Update("is_revoked", true)

	// Mark session 2 as expired
	past := time.Now().Add(-2 * time.Hour)
	_ = gdb.Model(&models.Session{}).Where("id = ?", t2.SessionID).Update("expires_at", past)

	// Query active sessions passing t3.SessionID as current
	sessions, err := svc.ListActiveSessions(ctx, user.ID, t3.SessionID)
	if err != nil {
		t.Fatalf("failed listing active sessions: %v", err)
	}

	// Exactly 1 active session should remain (session 3)
	if len(sessions) != 1 {
		t.Fatalf("expected exactly 1 active session, got %d", len(sessions))
	}

	if sessions[0].ID != t3.SessionID {
		t.Errorf("expected session 3 ID, got: %s", sessions[0].ID)
	}
	if !sessions[0].IsCurrent {
		t.Errorf("expected is_current = true for current session")
	}
}

func TestSession_RevokeSingle_Success(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "session-revoke@example.com"
	pass := "Str0ng#Pass123"

	user, err := svc.Register(ctx, "Revoke User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, tokens, err := svc.Login(ctx, email, pass)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	err = svc.RevokeSession(ctx, tokens.SessionID, user.ID)
	if err != nil {
		t.Fatalf("failed revoking session: %v", err)
	}

	// Verify session marked revoked
	var sess models.Session
	if err := gdb.First(&sess, "id = ?", tokens.SessionID).Error; err != nil {
		t.Fatalf("failed querying session: %v", err)
	}
	if !sess.IsRevoked {
		t.Errorf("expected session.is_revoked to be true")
	}

	// Verify linked refresh token marked revoked
	var rt models.RefreshToken
	if err := gdb.First(&rt, "session_id = ?", tokens.SessionID).Error; err != nil {
		t.Fatalf("failed querying refresh token: %v", err)
	}
	if !rt.IsRevoked {
		t.Errorf("expected refresh_token.is_revoked to be true")
	}
}

func TestSession_RevokeSingle_TenantIsolation(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	// User A
	userA, _ := svc.Register(ctx, "User A", "user-a@example.com", "Str0ng#Pass123")
	_, tokensA, _ := svc.Login(ctx, "user-a@example.com", "Str0ng#Pass123")

	// User B
	_, _ = svc.Register(ctx, "User B", "user-b@example.com", "Str0ng#Pass123")
	_, tokensB, _ := svc.Login(ctx, "user-b@example.com", "Str0ng#Pass123")

	// User A attempts to revoke User B's session
	err := svc.RevokeSession(ctx, tokensB.SessionID, userA.ID)
	if !errors.Is(err, httpx.ErrNotFound) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: expected ErrNotFound when User A attempts to revoke User B session, got: %v", err)
	}

	// Assert User B's session is still active
	var sessB models.Session
	_ = gdb.First(&sessB, "id = ?", tokensB.SessionID)
	if sessB.IsRevoked {
		t.Fatalf("User B's session was wrongfully revoked by User A!")
	}

	// Assert User A's session is still active
	var sessA models.Session
	_ = gdb.First(&sessA, "id = ?", tokensA.SessionID)
	if sessA.IsRevoked {
		t.Fatalf("User A's session was unexpectedly revoked")
	}
}

func TestSession_RevokeBulk_ExcludeCurrent(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "bulk-exclude@example.com"
	pass := "Str0ng#Pass123"

	user, err := svc.Register(ctx, "Bulk User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, t1, _ := svc.Login(ctx, email, pass)
	_, t2, _ := svc.Login(ctx, email, pass)
	_, t3, _ := svc.Login(ctx, email, pass)

	// Revoke all except current session (t3)
	count, err := svc.RevokeAllSessions(ctx, user.ID, t3.SessionID, true)
	if err != nil {
		t.Fatalf("failed revoking other sessions: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected count 2, got: %d", count)
	}

	var s1, s2, s3 models.Session
	_ = gdb.First(&s1, "id = ?", t1.SessionID)
	_ = gdb.First(&s2, "id = ?", t2.SessionID)
	_ = gdb.First(&s3, "id = ?", t3.SessionID)

	if !s1.IsRevoked || !s2.IsRevoked {
		t.Errorf("expected s1 and s2 to be revoked")
	}
	if s3.IsRevoked {
		t.Errorf("expected current session s3 to remain active")
	}
}

func TestSession_RevokeBulk_All(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "bulk-all@example.com"
	pass := "Str0ng#Pass123"

	user, err := svc.Register(ctx, "All User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, t1, _ := svc.Login(ctx, email, pass)
	_, t2, _ := svc.Login(ctx, email, pass)
	_, t3, _ := svc.Login(ctx, email, pass)

	// Revoke all sessions
	count, err := svc.RevokeAllSessions(ctx, user.ID, t3.SessionID, false)
	if err != nil {
		t.Fatalf("failed revoking all sessions: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected count 3, got: %d", count)
	}

	var s1, s2, s3 models.Session
	_ = gdb.First(&s1, "id = ?", t1.SessionID)
	_ = gdb.First(&s2, "id = ?", t2.SessionID)
	_ = gdb.First(&s3, "id = ?", t3.SessionID)

	if !s1.IsRevoked || !s2.IsRevoked || !s3.IsRevoked {
		t.Errorf("expected all 3 sessions to be revoked")
	}
}

func TestSession_HTTPHandlers_Integration(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	handler := NewHandler(svc)

	jwtVerifier := security.NewJWTVerifier([]byte("super-secret-test-key-32bytes!!"))
	jwtService := security.NewJWTService(jwtVerifier)
	authMiddleware := security.RequireAuth(jwtService, gdb)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, authMiddleware)

	ctx := context.Background()
	email := "http-sessions@example.com"
	pass := "Str0ng#Pass123"

	_, err := svc.Register(ctx, "HTTP User", email, pass)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, t1, _ := svc.Login(ctx, email, pass, ClientInfo{Device: "MacBook Pro"})
	_, t2, _ := svc.Login(ctx, email, pass, ClientInfo{Device: "iPhone 15"})

	// 1. GET /auth/sessions with t2's token
	req := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+t2.AccessToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on GET /auth/sessions, got: %d (%s)", rec.Code, rec.Body.String())
	}

	var listResp apiv1.SuccessListSessionsResponse
	if err := json.NewDecoder(rec.Body).Decode(&listResp); err != nil {
		t.Fatalf("failed decoding response: %v", err)
	}
	if listResp.Sessions == nil || len(*listResp.Sessions) != 2 {
		t.Fatalf("expected 2 active sessions in response")
	}

	// 2. DELETE /auth/sessions/{id} revoking session 1
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/sessions/"+t1.SessionID, nil)
	delReq.Header.Set("Authorization", "Bearer "+t2.AccessToken)
	delRec := httptest.NewRecorder()
	r.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on DELETE /auth/sessions/{id}, got: %d", delRec.Code)
	}

	// 3. GET /auth/sessions again: should now only return 1 session
	req2 := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	req2.Header.Set("Authorization", "Bearer "+t2.AccessToken)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)

	var listResp2 apiv1.SuccessListSessionsResponse
	_ = json.NewDecoder(rec2.Body).Decode(&listResp2)
	if listResp2.Sessions == nil || len(*listResp2.Sessions) != 1 {
		t.Fatalf("expected 1 active session after single revocation")
	}
	if (*listResp2.Sessions)[0].Id != t2.SessionID {
		t.Errorf("expected remaining session to be session 2")
	}

	// 4. DELETE /auth/sessions?exclude_current=true
	delAllReq := httptest.NewRequest(http.MethodDelete, "/auth/sessions?exclude_current=true", nil)
	delAllReq.Header.Set("Authorization", "Bearer "+t2.AccessToken)
	delAllRec := httptest.NewRecorder()
	r.ServeHTTP(delAllRec, delAllReq)

	if delAllRec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on DELETE /auth/sessions, got: %d", delAllRec.Code)
	}
}
