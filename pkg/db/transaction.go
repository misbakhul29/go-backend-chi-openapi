package db

import (
	"context"
	"errors"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	"gorm.io/gorm"
)

var (
	ErrNilDB     = errors.New("database connection cannot be nil")
	ErrNilTxFunc = errors.New("transaction function cannot be nil")
)

type contextKey string

const (
	TxContextKey contextKey = "db_tx"
)

func isTenantEnabled() bool {
	if config.Cfg != nil {
		return config.Cfg.Database.EnableMultiTenant
	}
	return false
}

func WithTenantID(ctx context.Context, tenantID string) context.Context {
	if !isTenantEnabled() {
		return ctx
	}
	return context.WithValue(ctx, observer.TenantIDKey, tenantID)
}

func GetTenantID(ctx context.Context) string {
	if !isTenantEnabled() {
		return ""
	}
	if val, ok := ctx.Value(observer.TenantIDKey).(string); ok {
		return val
	}
	return ""
}

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, observer.UserIDKey, userID)
}

func GetUserID(ctx context.Context) string {
	if val, ok := ctx.Value(observer.UserIDKey).(string); ok {
		return val
	}
	return ""
}

func isPostgresDialect(tx *gorm.DB) bool {
	return tx != nil && tx.Config != nil && tx.Dialector != nil && tx.Dialector.Name() == "postgres"
}

func WithTx(ctx context.Context, db *gorm.DB, fn func(txCtx context.Context, tx *gorm.DB) error) error {
	if fn == nil {
		return ErrNilTxFunc
	}

	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	if existingTx, ok := ctx.Value(TxContextKey).(*gorm.DB); ok && existingTx != nil {
		return fn(ctx, existingTx)
	}

	if db == nil {
		return ErrNilDB
	}

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if isPostgresDialect(tx) {
			if isTenantEnabled() {
				tenantID := GetTenantID(ctx)
				if tenantID != "" {
					if err := tx.Exec("SELECT set_config('app.tenant_id', ?, true)", tenantID).Error; err != nil {
						return err
					}
				}
			}

			userID := GetUserID(ctx)
			if userID != "" {
				if err := tx.Exec("SELECT set_config('app.user_id', ?, true)", userID).Error; err != nil {
					return err
				}
			}
		}

		txCtx := context.WithValue(ctx, TxContextKey, tx)
		return fn(txCtx, tx)
	})
}
