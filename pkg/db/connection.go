package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

func InitDB(cfg config.Database, permissions []string) (*gorm.DB, error) {
	gormLogger := logger.New(
		slog.NewLogLogger(observer.Log.Handler(), slog.LevelInfo),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	db, err := gorm.Open(postgres.Open(cfg.DatabaseUrl()), &gorm.Config{
		Logger:                                   gormLogger,
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		observer.Log.Error("failed to connect database", slog.Any("error", err))
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		observer.Log.Error("failed to get sql.DB instance", slog.Any("error", err))
		return nil, err
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	err = Migration(db, permissions)
	if err != nil {
		observer.Log.Error("database migration failed", slog.Any("error", err))
		return nil, err
	}

	observer.Log.Info("database connection established successfully")
	return db, nil
}

func CloseDB(db *gorm.DB) error {
	if db != nil {
		sqlDB, err := db.DB()
		if err == nil {
			observer.Log.Info("database connection closed")
			return sqlDB.Close()
		}
	}
	return nil
}

func PingDB(ctx context.Context, db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func Migration(db *gorm.DB, permissions []string) error {
	quietDB := db.Session(&gorm.Session{Logger: logger.Discard})
	err := quietDB.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.Account{},
		&models.Verification{},
		&models.Role{},
		&models.Permission{},
	)
	if err != nil && !strings.Contains(err.Error(), "42704") {
		observer.Log.Warn("AutoMigrate schema notice", "error", err)
	}

	// Seed GORM roles and permissions on startup
	if err := seedRolesAndPermissions(db, permissions); err != nil {
		observer.Log.Error("failed to seed roles and permissions", "error", err)
		return err
	}

	return nil
}

func seedRolesAndPermissions(dbClient *gorm.DB, permissions []string) error {
	var perms []models.Permission
	for _, code := range permissions {
		// Generate a stable UUID from the permission code string
		permUUID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(code)).String()
		p := models.Permission{
			ID:        permUUID,
			Code:      code,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := dbClient.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
		}).Create(&p).Error; err != nil {
			return err
		}
		perms = append(perms, p)
	}

	adminRole := models.Role{
		ID:        uuid.NewSHA1(uuid.NameSpaceDNS, []byte("ADMIN")).String(),
		Name:      "ADMIN",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := dbClient.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
	}).Create(&adminRole).Error; err != nil {
		return err
	}

	if err := dbClient.Model(&adminRole).Association("Permissions").Replace(perms); err != nil {
		return err
	}

	memberRole := models.Role{
		ID:        uuid.NewSHA1(uuid.NameSpaceDNS, []byte("MEMBER")).String(),
		Name:      "MEMBER",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := dbClient.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"updated_at"}),
	}).Create(&memberRole).Error; err != nil {
		return err
	}

	var memberPerms []models.Permission
	if err := dbClient.Model(&memberRole).Association("Permissions").Replace(memberPerms); err != nil {
		return err
	}

	return nil
}
