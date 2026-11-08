package db

import (
	"fmt"
	"testing"

	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupMigrationTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:mem_%s?mode=memory&cache=shared&_foreign_keys=ON&_busy_timeout=5000", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	return db
}

// 1. Verify Migration Evolution & Idempotency across successive runs
func TestAdversarial_Migration_SuccessiveUpgrades(t *testing.T) {
	db := setupMigrationTestDB(t)

	// Step 1: Initial migration with 2 permissions
	perms1 := []string{"auth:read", "auth:write"}
	if err := Migration(db, perms1); err != nil {
		t.Fatalf("step 1 migration failed: %v", err)
	}

	var permCount1 int64
	db.Model(&models.Permission{}).Count(&permCount1)
	if permCount1 != 2 {
		t.Errorf("step 1: expected 2 permissions, got %d", permCount1)
	}

	var adminRole models.Role
	if err := db.Preload("Permissions").Where("name = ?", models.RoleAdmin).First(&adminRole).Error; err != nil {
		t.Fatalf("failed to query admin role: %v", err)
	}
	if len(adminRole.Permissions) != 2 {
		t.Errorf("step 1: expected admin to have 2 permissions, got %d", len(adminRole.Permissions))
	}

	// Step 2: Second migration adding 2 more permissions
	perms2 := []string{"auth:read", "auth:write", "users:manage", "audit:view"}
	if err := Migration(db, perms2); err != nil {
		t.Fatalf("step 2 migration failed: %v", err)
	}

	var permCount2 int64
	db.Model(&models.Permission{}).Count(&permCount2)
	if permCount2 != 4 {
		t.Errorf("step 2: expected 4 permissions, got %d", permCount2)
	}

	if err := db.Preload("Permissions").Where("name = ?", models.RoleAdmin).First(&adminRole).Error; err != nil {
		t.Fatalf("failed to query admin role after step 2: %v", err)
	}
	if len(adminRole.Permissions) != 4 {
		t.Errorf("step 2: expected admin to have 4 permissions, got %d", len(adminRole.Permissions))
	}

	// Verify Member role has 0 permissions
	var memberRole models.Role
	if err := db.Preload("Permissions").Where("name = ?", models.RoleMember).First(&memberRole).Error; err != nil {
		t.Fatalf("failed to query member role: %v", err)
	}
	if len(memberRole.Permissions) != 0 {
		t.Errorf("step 2: expected member to have 0 permissions, got %d", len(memberRole.Permissions))
	}
}

// 2. Verify Migration handles duplicates in input permissions slice
func TestAdversarial_Migration_DuplicatePermissionsSlice(t *testing.T) {
	db := setupMigrationTestDB(t)

	// Slice with duplicated entries
	dupPerms := []string{"auth:login", "auth:login", "auth:login", "auth:logout"}
	if err := Migration(db, dupPerms); err != nil {
		t.Fatalf("migration with duplicate perms failed: %v", err)
	}

	var count int64
	db.Model(&models.Permission{}).Count(&count)
	if count != 2 {
		t.Errorf("expected 2 unique permissions, got %d", count)
	}
}

// 3. Verify Migration handles empty and nil permissions slice cleanly
func TestAdversarial_Migration_EmptyPermissions(t *testing.T) {
	db := setupMigrationTestDB(t)

	// Empty slice
	if err := Migration(db, []string{}); err != nil {
		t.Fatalf("migration with empty slice failed: %v", err)
	}

	// Nil slice
	if err := Migration(db, nil); err != nil {
		t.Fatalf("migration with nil slice failed: %v", err)
	}

	// Roles ADMIN and MEMBER must still exist
	var rolesCount int64
	db.Model(&models.Role{}).Count(&rolesCount)
	if rolesCount != 2 {
		t.Errorf("expected 2 roles (ADMIN, MEMBER), got %d", rolesCount)
	}
}
