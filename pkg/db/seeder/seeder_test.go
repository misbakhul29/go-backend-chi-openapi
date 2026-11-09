package seeder

import (
	"fmt"
	"testing"

	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupSeederTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:mem_%s?mode=memory&cache=shared&_foreign_keys=ON&_busy_timeout=5000", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	if err := db.AutoMigrate(&models.Role{}, &models.Permission{}); err != nil {
		t.Fatalf("failed to migrate schema: %v", err)
	}

	return db
}

func TestSeedRolesAndPermissions(t *testing.T) {
	db := setupSeederTestDB(t)

	permissions := []string{"users:read", "users:write"}
	if err := SeedRolesAndPermissions(db, permissions); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	var permCount int64
	db.Model(&models.Permission{}).Count(&permCount)
	if permCount != 2 {
		t.Errorf("expected 2 permissions, got %d", permCount)
	}

	var adminRole models.Role
	if err := db.Preload("Permissions").Where("name = ?", models.RoleAdmin).First(&adminRole).Error; err != nil {
		t.Fatalf("admin role not found: %v", err)
	}
	if len(adminRole.Permissions) != 2 {
		t.Errorf("expected admin to have 2 permissions, got %d", len(adminRole.Permissions))
	}

	var memberRole models.Role
	if err := db.Preload("Permissions").Where("name = ?", models.RoleMember).First(&memberRole).Error; err != nil {
		t.Fatalf("member role not found: %v", err)
	}
	if !memberRole.IsDefault {
		t.Errorf("expected member role to be default")
	}
	if len(memberRole.Permissions) != 0 {
		t.Errorf("expected member to have 0 permissions, got %d", len(memberRole.Permissions))
	}

	// Verify idempotency on second run
	if err := SeedRolesAndPermissions(db, permissions); err != nil {
		t.Fatalf("subsequent seed run failed: %v", err)
	}

	var roleCount int64
	db.Model(&models.Role{}).Count(&roleCount)
	if roleCount != 2 {
		t.Errorf("expected exactly 2 roles, got %d", roleCount)
	}
}

