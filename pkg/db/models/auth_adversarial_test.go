package models

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:mem_%s?mode=memory&cache=shared&_foreign_keys=ON&_busy_timeout=5000", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite database: %v", err)
	}

	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1)
	}

	// Explicitly enable foreign keys in SQLite
	if err := db.Exec("PRAGMA foreign_keys = ON;").Error; err != nil {
		t.Fatalf("failed to enable foreign keys: %v", err)
	}

	// Auto-migrate all models
	err = db.AutoMigrate(
		&User{},
		&Session{},
		&Account{},
		&Verification{},
		&Role{},
		&Permission{},
		&RefreshToken{},
		&MfaBackupCode{},
		&AuditLog{},
	)
	if err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	return db
}

// 1. Verify Table Names for all 9 models
func TestModel_TableNames(t *testing.T) {
	expected := map[string]string{
		"User":          User{}.TableName(),
		"Role":          Role{}.TableName(),
		"Permission":    Permission{}.TableName(),
		"Session":       Session{}.TableName(),
		"RefreshToken":  RefreshToken{}.TableName(),
		"MfaBackupCode": MfaBackupCode{}.TableName(),
		"AuditLog":      AuditLog{}.TableName(),
		"Account":       Account{}.TableName(),
		"Verification":  Verification{}.TableName(),
	}

	shouldBe := map[string]string{
		"User":          "user",
		"Role":          "role",
		"Permission":    "permission",
		"Session":       "session",
		"RefreshToken":  "refresh_token",
		"MfaBackupCode": "mfa_backup_code",
		"AuditLog":      "audit_log",
		"Account":       "account",
		"Verification":  "verification",
	}

	for k, exp := range shouldBe {
		if expected[k] != exp {
			t.Errorf("model %s TableName mismatch: got %q, expected %q", k, expected[k], exp)
		}
	}
}

// 2. Verify Schema Auto-Migration Idempotency
func TestModel_AutoMigrate_Idempotency(t *testing.T) {
	db := setupTestDB(t)

	// Second run of AutoMigrate must be completely idempotent
	err := db.AutoMigrate(
		&User{},
		&Session{},
		&Account{},
		&Verification{},
		&Role{},
		&Permission{},
		&RefreshToken{},
		&MfaBackupCode{},
		&AuditLog{},
	)
	if err != nil {
		t.Fatalf("second AutoMigrate call failed: %v", err)
	}
}

// 3. Uniqueness Constraints (User.Email, Role.Name, Permission.Code, RefreshToken.TokenHash)
func TestModel_Uniqueness_Constraints(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now()

	// a. User Email Uniqueness
	u1 := User{
		ID:        uuid.NewString(),
		Name:      "User 1",
		Email:     "unique@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&u1).Error; err != nil {
		t.Fatalf("failed to insert u1: %v", err)
	}

	u2 := User{
		ID:        uuid.NewString(),
		Name:      "User 2",
		Email:     "unique@example.com", // Duplicate email
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&u2).Error; err == nil {
		t.Errorf("expected UNIQUE constraint error on duplicate user email, got nil")
	}

	// b. Role Name Uniqueness
	r1 := Role{
		ID:        uuid.NewString(),
		Name:      "UNIQUE_ROLE",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&r1).Error; err != nil {
		t.Fatalf("failed to insert r1: %v", err)
	}

	r2 := Role{
		ID:        uuid.NewString(),
		Name:      "UNIQUE_ROLE", // Duplicate role name
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&r2).Error; err == nil {
		t.Errorf("expected UNIQUE constraint error on duplicate role name, got nil")
	}

	// c. Permission Code Uniqueness
	p1 := Permission{
		ID:        uuid.NewString(),
		Code:      "perm:unique",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&p1).Error; err != nil {
		t.Fatalf("failed to insert p1: %v", err)
	}

	p2 := Permission{
		ID:        uuid.NewString(),
		Code:      "perm:unique", // Duplicate perm code
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&p2).Error; err == nil {
		t.Errorf("expected UNIQUE constraint error on duplicate permission code, got nil")
	}

	// d. RefreshToken TokenHash Uniqueness
	sess := Session{
		ID:        uuid.NewString(),
		UserID:    u1.ID,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&sess).Error; err != nil {
		t.Fatalf("failed to insert session: %v", err)
	}

	rt1 := RefreshToken{
		ID:        uuid.NewString(),
		SessionID: sess.ID,
		FamilyID:  "fam-1",
		TokenHash: "hash-token-unique",
		ExpiresAt: now.Add(7 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := db.Create(&rt1).Error; err != nil {
		t.Fatalf("failed to insert rt1: %v", err)
	}

	rt2 := RefreshToken{
		ID:        uuid.NewString(),
		SessionID: sess.ID,
		FamilyID:  "fam-2",
		TokenHash: "hash-token-unique", // Duplicate token hash
		ExpiresAt: now.Add(7 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := db.Create(&rt2).Error; err == nil {
		t.Errorf("expected UNIQUE constraint error on duplicate refresh token hash, got nil")
	}
}

// 4. Foreign Key Constraints & Cascades
func TestModel_ForeignKeys_And_Cascades(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now()

	// a. Reject orphan records without parent User
	orphanSession := Session{
		ID:        uuid.NewString(),
		UserID:    "non-existent-user-id",
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&orphanSession).Error; err == nil {
		t.Errorf("expected foreign key failure inserting session with non-existent UserID, got nil")
	}

	orphanAccount := Account{
		ID:         uuid.NewString(),
		AccountID:  "acc-99",
		ProviderID: "google",
		UserID:     "non-existent-user-id",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := db.Create(&orphanAccount).Error; err == nil {
		t.Errorf("expected foreign key failure inserting account with non-existent UserID, got nil")
	}

	orphanBackupCode := MfaBackupCode{
		ID:        uuid.NewString(),
		UserID:    "non-existent-user-id",
		CodeHash:  "hash99",
		CreatedAt: now,
	}
	if err := db.Create(&orphanBackupCode).Error; err == nil {
		t.Errorf("expected foreign key failure inserting backup code with non-existent UserID, got nil")
	}

	// b. Create User with child records
	user := User{
		ID:        uuid.NewString(),
		Name:      "Cascade User",
		Email:     "cascade@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	sess := Session{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		FamilyID:  "fam-cascade",
		TokenHash: "hash-sess-1",
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&sess).Error; err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	rt := RefreshToken{
		ID:        uuid.NewString(),
		SessionID: sess.ID,
		FamilyID:  sess.FamilyID,
		TokenHash: "hash-rt-1",
		ExpiresAt: now.Add(7 * 24 * time.Hour),
		CreatedAt: now,
	}
	if err := db.Create(&rt).Error; err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	acc := Account{
		ID:         uuid.NewString(),
		AccountID:  "google-acc-1",
		ProviderID: "google",
		UserID:     user.ID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := db.Create(&acc).Error; err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	backupCode := MfaBackupCode{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		CodeHash:  "backup-hash-1",
		CreatedAt: now,
	}
	if err := db.Create(&backupCode).Error; err != nil {
		t.Fatalf("failed to create backup code: %v", err)
	}

	// Associate user with a role
	role := Role{
		ID:        uuid.NewString(),
		Name:      "CASCADE_ROLE",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&role).Error; err != nil {
		t.Fatalf("failed to create role: %v", err)
	}
	if err := db.Model(&user).Association("Roles").Append(&role); err != nil {
		t.Fatalf("failed to associate user role: %v", err)
	}

	// Verify counts before delete
	var sessCount, accCount, rtCount, bcCount, urCount int64
	db.Model(&Session{}).Where("user_id = ?", user.ID).Count(&sessCount)
	db.Model(&Account{}).Where("user_id = ?", user.ID).Count(&accCount)
	db.Model(&RefreshToken{}).Where("session_id = ?", sess.ID).Count(&rtCount)
	db.Model(&MfaBackupCode{}).Where("user_id = ?", user.ID).Count(&bcCount)
	db.Table("user_roles").Where("user_id = ?", user.ID).Count(&urCount)

	if sessCount != 1 || accCount != 1 || rtCount != 1 || bcCount != 1 || urCount != 1 {
		t.Fatalf("pre-delete count mismatch: sess=%d, acc=%d, rt=%d, bc=%d, ur=%d", sessCount, accCount, rtCount, bcCount, urCount)
	}

	// c. Delete User -> Must cascade delete Sessions, Accounts, BackupCodes, user_roles
	if err := db.Select(
		"Sessions.RefreshTokens",
		"Sessions",
		"Accounts",
		"BackupCodes",
		"Roles",
	).Delete(&user).Error; err != nil {
		t.Fatalf("failed to delete user with cascades: %v", err)
	}

	// Check post-delete counts
	db.Model(&Session{}).Where("user_id = ?", user.ID).Count(&sessCount)
	db.Model(&Account{}).Where("user_id = ?", user.ID).Count(&accCount)
	db.Model(&RefreshToken{}).Where("session_id = ?", sess.ID).Count(&rtCount)
	db.Model(&MfaBackupCode{}).Where("user_id = ?", user.ID).Count(&bcCount)
	db.Table("user_roles").Where("user_id = ?", user.ID).Count(&urCount)

	if sessCount != 0 {
		t.Errorf("expected 0 sessions after user cascade delete, got %d", sessCount)
	}
	if accCount != 0 {
		t.Errorf("expected 0 accounts after user cascade delete, got %d", accCount)
	}
	if rtCount != 0 {
		t.Errorf("expected 0 refresh tokens after session cascade delete, got %d", rtCount)
	}
	if bcCount != 0 {
		t.Errorf("expected 0 backup codes after user cascade delete, got %d", bcCount)
	}
	if urCount != 0 {
		t.Errorf("expected 0 user_roles join rows after user cascade delete, got %d", urCount)
	}

	// Role itself must NOT be deleted
	var roleCount int64
	db.Model(&Role{}).Where("id = ?", role.ID).Count(&roleCount)
	if roleCount != 1 {
		t.Errorf("expected role to remain intact, found %d", roleCount)
	}
}

// 5. Default Values and Field Nullability
func TestModel_DefaultValues(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now()

	// Insert User relying on default values
	user := User{
		ID:        uuid.NewString(),
		Name:      "Default User",
		Email:     "defaults@example.com",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	var fetchedUser User
	if err := db.First(&fetchedUser, "id = ?", user.ID).Error; err != nil {
		t.Fatalf("failed to fetch user: %v", err)
	}

	if fetchedUser.EmailVerified != false {
		t.Errorf("expected EmailVerified default false, got %v", fetchedUser.EmailVerified)
	}
	if fetchedUser.MfaEnabled != false {
		t.Errorf("expected MfaEnabled default false, got %v", fetchedUser.MfaEnabled)
	}
	if fetchedUser.IsActive != true {
		t.Errorf("expected IsActive default true, got %v", fetchedUser.IsActive)
	}

	// Insert Role relying on default IsDefault
	role := Role{
		ID:        uuid.NewString(),
		Name:      "CUSTOM_ROLE",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&role).Error; err != nil {
		t.Fatalf("failed to insert role: %v", err)
	}

	var fetchedRole Role
	if err := db.First(&fetchedRole, "id = ?", role.ID).Error; err != nil {
		t.Fatalf("failed to fetch role: %v", err)
	}
	if fetchedRole.IsDefault != false {
		t.Errorf("expected Role.IsDefault default false, got %v", fetchedRole.IsDefault)
	}

	// Insert Session relying on default IsRevoked
	sess := Session{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Create(&sess).Error; err != nil {
		t.Fatalf("failed to insert session: %v", err)
	}

	var fetchedSess Session
	if err := db.First(&fetchedSess, "id = ?", sess.ID).Error; err != nil {
		t.Fatalf("failed to fetch session: %v", err)
	}
	if fetchedSess.IsRevoked != false {
		t.Errorf("expected Session.IsRevoked default false, got %v", fetchedSess.IsRevoked)
	}

	// Insert RefreshToken relying on default IsRevoked
	rt := RefreshToken{
		ID:        uuid.NewString(),
		SessionID: sess.ID,
		FamilyID:  "fam-def",
		TokenHash: "hash-def-1",
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}
	if err := db.Create(&rt).Error; err != nil {
		t.Fatalf("failed to insert refresh token: %v", err)
	}

	var fetchedRT RefreshToken
	if err := db.First(&fetchedRT, "id = ?", rt.ID).Error; err != nil {
		t.Fatalf("failed to fetch refresh token: %v", err)
	}
	if fetchedRT.IsRevoked != false {
		t.Errorf("expected RefreshToken.IsRevoked default false, got %v", fetchedRT.IsRevoked)
	}

	// Insert MfaBackupCode relying on default IsUsed
	bc := MfaBackupCode{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		CodeHash:  "bc-hash-def",
		CreatedAt: now,
	}
	if err := db.Create(&bc).Error; err != nil {
		t.Fatalf("failed to insert backup code: %v", err)
	}

	var fetchedBC MfaBackupCode
	if err := db.First(&fetchedBC, "id = ?", bc.ID).Error; err != nil {
		t.Fatalf("failed to fetch backup code: %v", err)
	}
	if fetchedBC.IsUsed != false {
		t.Errorf("expected MfaBackupCode.IsUsed default false, got %v", fetchedBC.IsUsed)
	}
}

// 6. Verification and AuditLog Models
func TestModel_Verification_And_AuditLog(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now()

	// Verification model test
	v := Verification{
		ID:         uuid.NewString(),
		Identifier: "alice@example.com",
		Value:      "token-hash-123456",
		ExpiresAt:  now.Add(15 * time.Minute),
		CreatedAt:  &now,
		UpdatedAt:  &now,
	}
	if err := db.Create(&v).Error; err != nil {
		t.Fatalf("failed to insert verification: %v", err)
	}

	var fetchedV Verification
	if err := db.First(&fetchedV, "identifier = ? AND value = ?", v.Identifier, v.Value).Error; err != nil {
		t.Fatalf("failed to find verification: %v", err)
	}
	if fetchedV.ID != v.ID {
		t.Errorf("verification ID mismatch: expected %s, got %s", v.ID, fetchedV.ID)
	}

	// AuditLog model test
	userID := uuid.NewString()
	tenantID := "tenant-alpha"
	ip := "192.168.1.100"
	ua := "Mozilla/5.0 TestBrowser"
	metadata := `{"provider":"github","ip":"192.168.1.100"}`

	al := AuditLog{
		ID:        uuid.NewString(),
		Timestamp: now,
		EventType: "AUTH_LOGIN_SUCCESS",
		UserID:    &userID,
		TenantID:  &tenantID,
		IPAddress: &ip,
		UserAgent: &ua,
		Status:    "SUCCESS",
		Metadata:  &metadata,
		CreatedAt: now,
	}
	if err := db.Create(&al).Error; err != nil {
		t.Fatalf("failed to insert audit log: %v", err)
	}

	var fetchedAL AuditLog
	if err := db.First(&fetchedAL, "id = ?", al.ID).Error; err != nil {
		t.Fatalf("failed to find audit log: %v", err)
	}
	if fetchedAL.EventType != "AUTH_LOGIN_SUCCESS" || *fetchedAL.TenantID != tenantID || *fetchedAL.UserID != userID {
		t.Errorf("audit log content mismatch: %+v", fetchedAL)
	}
}

// 7. Concurrent Model Operations under Race Detector
func TestModel_ConcurrentOperations(t *testing.T) {
	db := setupTestDB(t)

	const goroutines = 25
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			now := time.Now()
			u := User{
				ID:        fmt.Sprintf("user-%04d", idx),
				Name:      fmt.Sprintf("Concurrent User %d", idx),
				Email:     fmt.Sprintf("concurrent-%04d@example.com", idx),
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := db.Create(&u).Error; err != nil {
				errCh <- fmt.Errorf("create user %d error: %w", idx, err)
				return
			}

			s := Session{
				ID:        fmt.Sprintf("session-%04d", idx),
				UserID:    u.ID,
				FamilyID:  fmt.Sprintf("fam-%04d", idx),
				TokenHash: fmt.Sprintf("th-%04d", idx),
				ExpiresAt: now.Add(24 * time.Hour),
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := db.Create(&s).Error; err != nil {
				errCh <- fmt.Errorf("create session %d error: %w", idx, err)
				return
			}

			rt := RefreshToken{
				ID:        fmt.Sprintf("rt-%04d", idx),
				SessionID: s.ID,
				FamilyID:  s.FamilyID,
				TokenHash: fmt.Sprintf("rt-hash-%04d", idx),
				ExpiresAt: now.Add(7 * 24 * time.Hour),
				CreatedAt: now,
			}
			if err := db.Create(&rt).Error; err != nil {
				errCh <- fmt.Errorf("create rt %d error: %w", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent model error: %v", err)
	}

	var userCount, sessCount, rtCount int64
	db.Model(&User{}).Where("id LIKE 'user-%'").Count(&userCount)
	db.Model(&Session{}).Where("id LIKE 'session-%'").Count(&sessCount)
	db.Model(&RefreshToken{}).Where("id LIKE 'rt-%'").Count(&rtCount)

	if userCount != goroutines || sessCount != goroutines || rtCount != goroutines {
		t.Errorf("expected %d rows each, got user=%d, sess=%d, rt=%d", goroutines, userCount, sessCount, rtCount)
	}
}
