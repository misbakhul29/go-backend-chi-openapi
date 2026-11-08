package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type TestItem struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"type:varchar(255)"`
}

func setupTestSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite db: %v", err)
	}
	if err := db.AutoMigrate(&TestItem{}); err != nil {
		t.Fatalf("failed to automigrate TestItem: %v", err)
	}
	return db
}

func TestTenantID_ConfigDisabled(t *testing.T) {
	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()

	config.Cfg = &config.Env{
		Database: config.Database{
			EnableMultiTenant: false,
		},
	}

	ctx := context.Background()
	ctx = WithTenantID(ctx, "tenant-123")

	if id := GetTenantID(ctx); id != "" {
		t.Errorf("expected empty tenant id when disabled, got %q", id)
	}

	if val := ctx.Value(observer.TenantIDKey); val != nil {
		t.Errorf("expected context value to be nil when disabled, got %v", val)
	}
}

func TestTenantID_ConfigEnabled(t *testing.T) {
	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()

	config.Cfg = &config.Env{
		Database: config.Database{
			EnableMultiTenant: true,
		},
	}

	ctx := context.Background()
	ctx = WithTenantID(ctx, "tenant-123")

	if id := GetTenantID(ctx); id != "tenant-123" {
		t.Errorf("expected tenant-123, got %q", id)
	}
}

func TestUserID_Context(t *testing.T) {
	ctx := context.Background()
	if id := GetUserID(ctx); id != "" {
		t.Errorf("expected empty user id, got %q", id)
	}

	ctx = WithUserID(ctx, "user-456")
	if id := GetUserID(ctx); id != "user-456" {
		t.Errorf("expected 'user-456', got %q", id)
	}
}

func TestWithTx_SQLite_SkipsSetConfig(t *testing.T) {
	db := setupTestSQLite(t)

	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()

	config.Cfg = &config.Env{
		Database: config.Database{
			EnableMultiTenant: true,
		},
	}

	ctx := context.Background()
	ctx = WithTenantID(ctx, "tenant-abc")
	ctx = WithUserID(ctx, "user-xyz")

	var callbackRan bool
	err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
		callbackRan = true
		if tx.Dialector.Name() != "sqlite" {
			t.Errorf("expected dialect 'sqlite', got %s", tx.Dialector.Name())
		}
		if txCtx.Value(TxContextKey) == nil {
			t.Errorf("expected TxContextKey in txCtx")
		}
		return tx.Create(&TestItem{Name: "item-1"}).Error
	})

	if err != nil {
		t.Fatalf("expected WithTx to succeed on SQLite, got error: %v", err)
	}
	if !callbackRan {
		t.Fatal("expected WithTx callback to execute")
	}

	var count int64
	db.Model(&TestItem{}).Where("name = ?", "item-1").Count(&count)
	if count != 1 {
		t.Errorf("expected count 1 after commit, got %d", count)
	}
}

func TestWithTx_NestedTransaction_ReusesExistingTx(t *testing.T) {
	db := setupTestSQLite(t)

	ctx := context.Background()
	var outerTx, innerTx *gorm.DB

	err := WithTx(ctx, db, func(txCtx context.Context, tx1 *gorm.DB) error {
		outerTx = tx1
		return WithTx(txCtx, db, func(innerCtx context.Context, tx2 *gorm.DB) error {
			innerTx = tx2
			return nil
		})
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outerTx != innerTx {
		t.Errorf("expected inner transaction to reuse outer transaction instance")
	}
}

func TestWithTx_RollbackOnFailure(t *testing.T) {
	db := setupTestSQLite(t)

	ctx := context.Background()
	expectedErr := errors.New("simulated business error")

	err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
		if err := tx.Create(&TestItem{Name: "rollback-item"}).Error; err != nil {
			return err
		}
		return expectedErr
	})

	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}

	var count int64
	db.Model(&TestItem{}).Where("name = ?", "rollback-item").Count(&count)
	if count != 0 {
		t.Errorf("expected 0 items after rollback, got %d", count)
	}
}

func TestIsPostgresDialect(t *testing.T) {
	if isPostgresDialect(nil) {
		t.Errorf("expected false for nil db")
	}

	if isPostgresDialect(&gorm.DB{}) {
		t.Errorf("expected false for uninitialized gorm.DB{}")
	}

	if isPostgresDialect(&gorm.DB{Config: &gorm.Config{}}) {
		t.Errorf("expected false for gorm.DB with nil dialector")
	}

	db := setupTestSQLite(t)
	if isPostgresDialect(db) {
		t.Errorf("expected false for sqlite db")
	}
}

func TestWithTx_NilGuards(t *testing.T) {
	ctx := context.Background()
	db := setupTestSQLite(t)

	if err := WithTx(ctx, nil, func(txCtx context.Context, tx *gorm.DB) error {
		return nil
	}); !errors.Is(err, ErrNilDB) {
		t.Errorf("expected ErrNilDB when db is nil, got %v", err)
	}

	if err := WithTx(ctx, db, nil); !errors.Is(err, ErrNilTxFunc) {
		t.Errorf("expected ErrNilTxFunc when fn is nil, got %v", err)
	}

	if err := WithTx(ctx, nil, nil); !errors.Is(err, ErrNilTxFunc) {
		t.Errorf("expected ErrNilTxFunc when both db and fn are nil, got %v", err)
	}

	ctxWithTx := context.WithValue(ctx, TxContextKey, db)
	if err := WithTx(ctxWithTx, db, nil); !errors.Is(err, ErrNilTxFunc) {
		t.Errorf("expected ErrNilTxFunc when fn is nil even with existing tx in ctx, got %v", err)
	}
}

func TestSchema_Evolution_And_Seeding(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	permissions := []string{"auth:read", "auth:write"}
	if err := Migration(db, permissions); err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify roles seeded with correct default flags
	var adminRole, memberRole models.Role
	if err := db.Where("name = ?", models.RoleAdmin).First(&adminRole).Error; err != nil {
		t.Fatalf("failed to query admin role: %v", err)
	}
	if adminRole.IsDefault {
		t.Errorf("expected ADMIN role IsDefault to be false, got true")
	}

	if err := db.Where("name = ?", models.RoleMember).First(&memberRole).Error; err != nil {
		t.Fatalf("failed to query member role: %v", err)
	}
	if !memberRole.IsDefault {
		t.Errorf("expected MEMBER role IsDefault to be true, got false")
	}

	// Verify User evolution fields
	now := time.Now()
	mfaSecret := "encrypted_mfa_secret"
	user := models.User{
		ID:            uuid.NewString(),
		Name:          "Test User",
		Email:         "test@example.com",
		EmailVerified: true,
		MfaEnabled:    true,
		MfaSecret:     &mfaSecret,
		IsActive:      true,
		LastLoginAt:   &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	var fetchedUser models.User
	if err := db.First(&fetchedUser, "id = ?", user.ID).Error; err != nil {
		t.Fatalf("failed to fetch user: %v", err)
	}
	if !fetchedUser.MfaEnabled || fetchedUser.MfaSecret == nil || *fetchedUser.MfaSecret != mfaSecret || !fetchedUser.IsActive {
		t.Errorf("user evolution fields mismatch: %+v", fetchedUser)
	}

	// Verify Session evolution fields
	session := models.Session{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: "session_hash_abc",
		FamilyID:  "family_123",
		IsRevoked: false,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&session).Error; err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Verify RefreshToken model
	refreshToken := models.RefreshToken{
		ID:        uuid.NewString(),
		SessionID: session.ID,
		FamilyID:  session.FamilyID,
		TokenHash: "refresh_hash_xyz",
		IsRevoked: false,
		ExpiresAt: now.Add(7 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := db.Create(&refreshToken).Error; err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	// Verify MfaBackupCode model
	backupCode := models.MfaBackupCode{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		CodeHash:  "backup_hash_code_1",
		IsUsed:    false,
		CreatedAt: now,
	}
	if err := db.Create(&backupCode).Error; err != nil {
		t.Fatalf("failed to create backup code: %v", err)
	}

	// Verify AuditLog model
	metadata := `{"action":"login_test"}`
	tenantID := "tenant-xyz"
	ipAddr := "127.0.0.1"
	auditLog := models.AuditLog{
		ID:        uuid.NewString(),
		Timestamp: now,
		EventType: "USER_LOGIN_SUCCESS",
		UserID:    &user.ID,
		TenantID:  &tenantID,
		IPAddress: &ipAddr,
		Status:    "SUCCESS",
		Metadata:  &metadata,
		CreatedAt: now,
	}
	if err := db.Create(&auditLog).Error; err != nil {
		t.Fatalf("failed to create audit log: %v", err)
	}

	var fetchedAudit models.AuditLog
	if err := db.First(&fetchedAudit, "id = ?", auditLog.ID).Error; err != nil {
		t.Fatalf("failed to fetch audit log: %v", err)
	}
	if fetchedAudit.EventType != "USER_LOGIN_SUCCESS" || fetchedAudit.Status != "SUCCESS" || fetchedAudit.Metadata == nil {
		t.Errorf("audit log mismatch: %+v", fetchedAudit)
	}
}
