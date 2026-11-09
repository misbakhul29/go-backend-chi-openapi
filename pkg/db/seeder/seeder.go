package seeder

import (
	"time"

	"github.com/google/uuid"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// SeedRolesAndPermissions populates default roles and attaches registered permissions.
func SeedRolesAndPermissions(db *gorm.DB, permissions []string) error {
	var perms []models.Permission
	for _, code := range permissions {
		// Use deterministic UUID based on permission code for idempotent seeding.
		permUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(code)).String()
		p := models.Permission{
			ID:        permUUID,
			Code:      code,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
		}).Create(&p).Error; err != nil {
			return err
		}
		perms = append(perms, p)
	}

	adminRole := models.Role{
		ID:        uuid.NewSHA1(uuid.NameSpaceDNS, []byte(models.RoleAdmin)).String(),
		Name:      models.RoleAdmin,
		IsDefault: false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"updated_at", "is_default"}),
	}).Create(&adminRole).Error; err != nil {
		return err
	}

	if err := db.Model(&adminRole).Association("Permissions").Replace(perms); err != nil {
		return err
	}

	memberRole := models.Role{
		ID:        uuid.NewSHA1(uuid.NameSpaceDNS, []byte(models.RoleMember)).String(),
		Name:      models.RoleMember,
		IsDefault: true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"updated_at", "is_default"}),
	}).Create(&memberRole).Error; err != nil {
		return err
	}

	var memberPerms []models.Permission
	if err := db.Model(&memberRole).Association("Permissions").Replace(memberPerms); err != nil {
		return err
	}

	return nil
}

