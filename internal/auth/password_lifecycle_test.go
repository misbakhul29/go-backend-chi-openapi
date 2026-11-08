package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/security"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbName := fmt.Sprintf("file:testdb_%d?mode=memory&cache=shared", time.Now().UnixNano())
	gdb, err := gorm.Open(sqlite.Open(dbName), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1)
	}

	permissions := []string{"system:admin", "users:read", "users:write"}
	if err := db.Migration(gdb, permissions); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	return gdb
}

func newTestAuthService(gdb *gorm.DB) (*AuthServiceImpl, AuthRepository) {
	repo := NewRepository(gdb)
	jwtCfg := config.JWT{
		Secret:     "super-secret-test-key-32bytes!!",
		AccessTTL:  900,
		RefreshTTL: 604800,
	}
	svc := NewService(repo, gdb, nil, jwtCfg)
	return svc, repo
}

func TestPasswordLifecycle_RegistrationValidation(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	// 1. Valid registration
	user, err := svc.Register(ctx, "Alice Wonder", "alice@example.com", "Str0ng#Pass123")
	if err != nil {
		t.Fatalf("expected valid registration to succeed, got: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("expected email to be normalized, got: %s", user.Email)
	}

	// 2. Email normalization (mixed case and trailing spaces)
	user2, err := svc.Register(ctx, "Bob Builder", "  Bob.Builder@Example.COM  ", "Str0ng#Pass456")
	if err != nil {
		t.Fatalf("expected normalized registration to succeed, got: %v", err)
	}
	if user2.Email != "bob.builder@example.com" {
		t.Errorf("expected email bob.builder@example.com, got: %s", user2.Email)
	}

	// 3. Invalid email formats
	invalidEmails := []string{"invalid", "@missinguser.com", "user@.com", ""}
	for _, ie := range invalidEmails {
		_, err := svc.Register(ctx, "Invalid User", ie, "Str0ng#Pass123")
		if !errors.Is(err, httpx.ErrValidation) {
			t.Errorf("expected ErrValidation for email %q, got: %v", ie, err)
		}
	}

	// 4. Password complexity failures
	weakPasswords := []string{
		"short1!",        // < 8 chars
		"nouppercase123!", // no uppercase
		"NOLOWERCASE123!", // no lowercase
		"NoDigitsHere!?", // no digits
		"NoSymbols12345", // no symbols
	}
	for _, wp := range weakPasswords {
		_, err := svc.Register(ctx, "Weak Pass User", fmt.Sprintf("weak_%d@example.com", time.Now().UnixNano()), wp)
		if !errors.Is(err, httpx.ErrValidation) {
			t.Errorf("expected ErrValidation for weak password %q, got: %v", wp, err)
		}
	}
}

func TestPasswordLifecycle_DuplicateEmailConflict(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	_, err := svc.Register(ctx, "First User", "duplicate@example.com", "Str0ng#Pass123")
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	_, err = svc.Register(ctx, "Second User", "duplicate@example.com", "Str0ng#Pass123")
	if !errors.Is(err, ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists on duplicate email, got: %v", err)
	}
}

func TestPasswordLifecycle_BruteForceLockout(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "target-lockout@example.com"
	correctPass := "Str0ng#Pass123"
	wrongPass := "Wrong#Pass123"

	_, err := svc.Register(ctx, "Target User", email, correctPass)
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	// First 4 failed attempts
	for i := 1; i <= 4; i++ {
		_, _, err := svc.Login(ctx, email, wrongPass)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got: %v", i, err)
		}
	}

	// 5th failed attempt triggers lockout
	_, _, err = svc.Login(ctx, email, wrongPass)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("5th attempt: expected ErrInvalidCredentials, got: %v", err)
	}

	// 6th attempt with correct password should be locked out
	_, _, err = svc.Login(ctx, email, correctPass)
	if !errors.Is(err, httpx.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked after 5 failures, got: %v", err)
	}

	// Reset lockout
	_ = security.ResetFailedAttempts(ctx, nil, email)

	// Now correct login succeeds
	user, tokens, err := svc.Login(ctx, email, correctPass)
	if err != nil {
		t.Fatalf("expected successful login after lockout reset, got: %v", err)
	}
	if user == nil || tokens == nil {
		t.Fatal("expected non-nil user and tokens on successful login")
	}
}

func TestPasswordLifecycle_TimingMitigation_NonExistentUser(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	// Login with nonexistent email should run dummy verification and return ErrInvalidCredentials
	_, _, err := svc.Login(ctx, "nonexistent@example.com", "Str0ng#Pass123")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for nonexistent user, got: %v", err)
	}
}

func TestPasswordLifecycle_ForgotPassword_AntiEnumeration(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	// 1. Non-existent email should return nil (no error, anti-enumeration)
	err := svc.ForgotPassword(ctx, "doesnotexist@example.com")
	if err != nil {
		t.Fatalf("expected nil for non-existent email, got: %v", err)
	}

	// 2. Existent user should create verification record
	user, err := svc.Register(ctx, "Forgot User", "forgot@example.com", "Str0ng#Pass123")
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	err = svc.ForgotPassword(ctx, "forgot@example.com")
	if err != nil {
		t.Fatalf("expected nil on forgot password for existent user, got: %v", err)
	}

	var count int64
	gdb.Model(&models.Verification{}).Where("identifier = ?", user.ID).Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 verification record in DB, got: %d", count)
	}
}

func TestPasswordLifecycle_ResetPassword(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "reset-target@example.com"
	oldPass := "Str0ng#Old123"
	newPass := "Str0ng#New456"

	user, err := svc.Register(ctx, "Reset Target", email, oldPass)
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	// Login once to establish a session
	_, tokens, err := svc.Login(ctx, email, oldPass)
	if err != nil {
		t.Fatalf("failed login: %v", err)
	}

	// Seed verification record
	rawToken, _ := security.GenerateOpaqueToken(32)
	tokenHash := security.HashToken(rawToken)
	now := time.Now()
	v := &models.Verification{
		ID:         "ver-test-1",
		Identifier: user.ID,
		Value:      tokenHash,
		ExpiresAt:  now.Add(15 * time.Minute),
		CreatedAt:  &now,
		UpdatedAt:  &now,
	}
	if err := gdb.Create(v).Error; err != nil {
		t.Fatalf("failed creating verification record: %v", err)
	}

	// 1. Weak new password rejected
	err = svc.ResetPassword(ctx, rawToken, "weakpass")
	if !errors.Is(err, httpx.ErrValidation) {
		t.Fatalf("expected ErrValidation on weak new password, got: %v", err)
	}

	// 2. Successful reset
	err = svc.ResetPassword(ctx, rawToken, newPass)
	if err != nil {
		t.Fatalf("reset password failed: %v", err)
	}

	// 3. Old password should fail
	_, _, err = svc.Login(ctx, email, oldPass)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected old password to fail after reset, got: %v", err)
	}

	// 4. New password succeeds
	_, _, err = svc.Login(ctx, email, newPass)
	if err != nil {
		t.Fatalf("expected new password to succeed, got: %v", err)
	}

	// 5. Verification token must be single-use (deleted from DB)
	err = svc.ResetPassword(ctx, rawToken, "Another#Pass123")
	if !errors.Is(err, httpx.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken on reused token, got: %v", err)
	}

	// 6. User's previous session should have been revoked
	var session models.Session
	if err := gdb.First(&session, "id = ?", tokens.SessionID).Error; err == nil {
		if !session.IsRevoked {
			t.Errorf("expected session to be marked is_revoked = true after password reset")
		}
	}
}

func TestPasswordLifecycle_ChangePassword(t *testing.T) {
	gdb := newTestDB(t)
	svc, _ := newTestAuthService(gdb)
	ctx := context.Background()

	email := "change-target@example.com"
	oldPass := "Str0ng#Old123"
	newPass := "Str0ng#New456"

	user, err := svc.Register(ctx, "Change Target", email, oldPass)
	if err != nil {
		t.Fatalf("failed registering user: %v", err)
	}

	// Login twice to create two sessions
	_, t1, err := svc.Login(ctx, email, oldPass)
	if err != nil {
		t.Fatalf("login 1 failed: %v", err)
	}
	_, t2, err := svc.Login(ctx, email, oldPass)
	if err != nil {
		t.Fatalf("login 2 failed: %v", err)
	}

	// 1. Wrong old password
	err = svc.ChangePassword(ctx, user.ID, "Wrong#Old123", newPass, false, t2.SessionID)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on wrong old password, got: %v", err)
	}

	// 2. Weak new password
	err = svc.ChangePassword(ctx, user.ID, oldPass, "short1!", false, t2.SessionID)
	if !errors.Is(err, httpx.ErrValidation) {
		t.Fatalf("expected ErrValidation on weak new password, got: %v", err)
	}

	// 3. Successful change with revokeOtherSessions = true
	err = svc.ChangePassword(ctx, user.ID, oldPass, newPass, true, t2.SessionID)
	if err != nil {
		t.Fatalf("failed changing password: %v", err)
	}

	// Verify session 1 is revoked, but session 2 remains unrevoked
	var s1, s2 models.Session
	if err := gdb.First(&s1, "id = ?", t1.SessionID).Error; err != nil {
		t.Fatalf("failed querying session 1: %v", err)
	}
	if err := gdb.First(&s2, "id = ?", t2.SessionID).Error; err != nil {
		t.Fatalf("failed querying session 2: %v", err)
	}

	if !s1.IsRevoked {
		t.Errorf("expected other session s1 to be revoked")
	}
	if s2.IsRevoked {
		t.Errorf("expected current session s2 to remain active")
	}
}
