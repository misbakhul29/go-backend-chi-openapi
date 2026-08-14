package db

import (
	"context"

	"github.com/misbakhul29/backend-framework/pkg/observer"
	"gorm.io/gorm"
)

type contextKey string

const (
	TxContextKey contextKey = "db_tx"
)

func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, observer.TenantIDKey, tenantID)
}

func GetTenantID(ctx context.Context) string {
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

func WithTx(ctx context.Context, db *gorm.DB, fn func(txCtx context.Context, tx *gorm.DB) error) error {
	if existingTx, ok := ctx.Value(TxContextKey).(*gorm.DB); ok && existingTx != nil {
		return fn(ctx, existingTx)
	}

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tenantID := GetTenantID(ctx)
		if tenantID != "" {
			if err := tx.Exec("SELECT set_config('app.tenant_id', ?, true)", tenantID).Error; err != nil {
				return err
			}
		}

		userID := GetUserID(ctx)
		if userID != "" {
			if err := tx.Exec("SELECT set_config('app.user_id', ?, true)", userID).Error; err != nil {
				return err
			}
		}

		txCtx := context.WithValue(ctx, TxContextKey, tx)
		return fn(txCtx, tx)
	})
}
