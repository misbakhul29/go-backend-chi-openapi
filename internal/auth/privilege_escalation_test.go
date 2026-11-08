package auth

import (
	"context"
	"testing"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAuthTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_busy_timeout=5000"), &gorm.Config{})
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

func TestPrivilegeEscalation_DefaultRoleIsMember(t *testing.T) {
	if models.DefaultRole != "MEMBER" {
		t.Fatalf("SECURITY VIOLATION: models.DefaultRole is %q, expected 'MEMBER'", models.DefaultRole)
	}
	if models.RoleMember != "MEMBER" {
		t.Fatalf("models.RoleMember is %q, expected 'MEMBER'", models.RoleMember)
	}
	if models.RoleAdmin != "ADMIN" {
		t.Fatalf("models.RoleAdmin is %q, expected 'ADMIN'", models.RoleAdmin)
	}
}

func TestPrivilegeEscalation_RegistrationAssignsMemberNotAdmin(t *testing.T) {
	gdb := setupAuthTestDB(t)
	repo := NewRepository(gdb)
	svc := NewService(repo, gdb, nil, config.JWT{Secret: "test-secret-32-bytes-long-key!!", AccessTTL: 900, RefreshTTL: 604800})

	ctx := context.Background()
	user, err := svc.Register(ctx, "Attacker Bob", "bob@example.com", "SuperSecretPassword123!")
	if err != nil {
		t.Fatalf("failed to register user: %v", err)
	}

	if user == nil {
		t.Fatal("expected registered user to be non-nil")
	}

	// 1. Check in-memory user return struct
	if len(user.Roles) == 0 {
		t.Fatal("user has no roles assigned")
	}
	for _, role := range user.Roles {
		if role.Name == models.RoleAdmin {
			t.Fatalf("CRITICAL SECURITY VIOLATION: newly registered user assigned ADMIN role!")
		}
		if role.Name != models.RoleMember {
			t.Errorf("expected role %s, got %s", models.RoleMember, role.Name)
		}
		if !role.IsDefault {
			t.Errorf("expected member role to have IsDefault=true")
		}
	}

	// 2. Query DB directly with fresh context to assert persistence
	var dbUser models.User
	if err := gdb.Preload("Roles").First(&dbUser, "id = ?", user.ID).Error; err != nil {
		t.Fatalf("failed to query user from DB: %v", err)
	}

	if len(dbUser.Roles) != 1 {
		t.Fatalf("expected exactly 1 role in DB, got %d", len(dbUser.Roles))
	}
	if dbUser.Roles[0].Name != models.RoleMember {
		t.Fatalf("persisted user role is %q, expected %q", dbUser.Roles[0].Name, models.RoleMember)
	}

	// 3. Verify user permissions do NOT include admin permissions
	perms, err := repo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user permissions: %v", err)
	}
	for _, perm := range perms {
		if perm == "system:admin" {
			t.Fatalf("CRITICAL SECURITY VIOLATION: newly registered user has admin permission %q", perm)
		}
	}
}

func TestPrivilegeEscalation_CannotSupplyRoleInRegister(t *testing.T) {
	// Assert the AuthService interface contract does not accept role in Register
	// Register(ctx context.Context, name, email, password string) (*models.User, error)
	var _ func(context.Context, string, string, string) (*models.User, error) = (&AuthServiceImpl{}).Register
}
