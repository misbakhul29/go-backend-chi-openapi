package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func InitDB(cfg config.Database) (*gorm.DB, error) {
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

	err = Migration(db)
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

func Migration(db *gorm.DB) error {
	quietDB := db.Session(&gorm.Session{Logger: logger.Discard})
	err := quietDB.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.Account{},
		&models.Verification{},
	)
	if err != nil && !strings.Contains(err.Error(), "42704") {
		observer.Log.Warn("AutoMigrate schema notice", "error", err)
	}

	return nil
}
