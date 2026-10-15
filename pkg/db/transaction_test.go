package db

import (
	"context"
	"testing"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/observer"
)

func TestTenantID_ConfigDisabled(t *testing.T) {
	config.Cfg = &config.Env{
		Database: config.Database{
			EnableMultiTenant: false,
		},
	}

	ctx := context.Background()
	ctx = WithTenantID(ctx, "tenant-123")

	if id := GetTenantID(ctx); id != "" {
		t.Errorf("expected empty tenant id when disabled, got %q", id)
	}

	if val := ctx.Value(observer.TenantIDKey); val != nil {
		t.Errorf("expected context value to be nil when disabled, got %v", val)
	}
}

func TestTenantID_ConfigEnabled(t *testing.T) {
	config.Cfg = &config.Env{
		Database: config.Database{
			EnableMultiTenant: true,
		},
	}

	ctx := context.Background()
	ctx = WithTenantID(ctx, "tenant-123")

	if id := GetTenantID(ctx); id != "tenant-123" {
		t.Errorf("expected tenant-123, got %q", id)
	}
}
