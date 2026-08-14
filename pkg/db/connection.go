package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/misbakhul29/backend-framework/config"
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

	_ = db.Callback().Create().Before("gorm:create").Register("set_tenant_context", setTenantContextCallback)
	_ = db.Callback().Query().Before("gorm:query").Register("set_tenant_context", setTenantContextCallback)
	_ = db.Callback().Update().Before("gorm:update").Register("set_tenant_context", setTenantContextCallback)
	_ = db.Callback().Delete().Before("gorm:delete").Register("set_tenant_context", setTenantContextCallback)

	observer.Log.Info("database connection established successfully")
	return db, nil
}

func setTenantContextCallback(db *gorm.DB) {
	if db.Statement == nil || db.Statement.Context == nil {
		return
	}
	ctx := db.Statement.Context
	if tid, ok := ctx.Value(observer.TenantIDKey).(string); ok && tid != "" {
		_ = db.Exec("SELECT set_config('app.tenant_id', ?, true)", tid).Error
	}
	if uid, ok := ctx.Value(observer.UserIDKey).(string); ok && uid != "" {
		_ = db.Exec("SELECT set_config('app.user_id', ?, true)", uid).Error
	}
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
	err := quietDB.AutoMigrate()
	if err != nil && !strings.Contains(err.Error(), "42704") {
		observer.Log.Warn("AutoMigrate schema notice", "error", err)
	}

	return nil
}
