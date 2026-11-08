package db

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/misbakhul29/backend-framework/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type StressItem struct {
	ID    uint   `gorm:"primaryKey"`
	Key   string `gorm:"type:varchar(100);uniqueIndex"`
	Value string `gorm:"type:varchar(255)"`
}

func setupStressDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_busy_timeout=5000"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := db.AutoMigrate(&StressItem{}); err != nil {
		t.Fatalf("failed to automigrate StressItem: %v", err)
	}
	// clean up table
	db.Exec("DELETE FROM stress_items")
	return db
}

// 1. Verify dialect safety: no set_config called on SQLite even with multi-tenant and user ID enabled
func TestDialectSafety_SQLite_NoSetConfig(t *testing.T) {
	db := setupStressDB(t)

	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()

	config.Cfg = &config.Env{
		Database: config.Database{
			EnableMultiTenant: true,
		},
	}

	ctx := context.Background()
	ctx = WithTenantID(ctx, "adversarial-tenant-999")
	ctx = WithUserID(ctx, "adversarial-user-888")

	err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
		item := StressItem{Key: "k1", Value: "v1"}
		return tx.Create(&item).Error
	})
	if err != nil {
		t.Fatalf("WithTx failed unexpectedly on SQLite: %v", err)
	}

	var count int64
	db.Model(&StressItem{}).Where("key = ?", "k1").Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 item, got %d", count)
	}
}

// 2. Verify complete transaction rollback: multi-step insertion fails midway -> ZERO partial commits
func TestDialectSafety_Rollback_NoPartialCommit(t *testing.T) {
	db := setupStressDB(t)

	ctx := context.Background()
	forcedErr := errors.New("aborted halfway through multi-step batch")

	err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
		if err := tx.Create(&StressItem{Key: "step-1", Value: "first"}).Error; err != nil {
			return err
		}
		if err := tx.Create(&StressItem{Key: "step-2", Value: "second"}).Error; err != nil {
			return err
		}
		// Failure before completion
		return forcedErr
	})

	if !errors.Is(err, forcedErr) {
		t.Fatalf("expected forcedErr, got %v", err)
	}

	var count1, count2 int64
	db.Model(&StressItem{}).Where("key = ?", "step-1").Count(&count1)
	db.Model(&StressItem{}).Where("key = ?", "step-2").Count(&count2)

	if count1 != 0 || count2 != 0 {
		t.Fatalf("PARTIAL COMMIT DETECTED! step-1: %d, step-2: %d (must be 0)", count1, count2)
	}
}

// 3. Verify rollback on panic inside WithTx
func TestDialectSafety_Rollback_OnPanic(t *testing.T) {
	db := setupStressDB(t)

	ctx := context.Background()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected panic to occur")
			}
		}()

		_ = WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
			if err := tx.Create(&StressItem{Key: "panic-item", Value: "doomed"}).Error; err != nil {
				return err
			}
			panic("unexpected runtime panic during transaction")
		})
	}()

	var count int64
	db.Model(&StressItem{}).Where("key = ?", "panic-item").Count(&count)
	if count != 0 {
		t.Fatalf("PARTIAL COMMIT ON PANIC! Expected 0, found %d", count)
	}
}

// 4. Concurrent transactions under -race
func TestDialectSafety_ConcurrentTransactions(t *testing.T) {
	db := setupStressDB(t)

	const goroutines = 20
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()
			err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
				item := StressItem{
					Key:   fmt.Sprintf("concurrent-%d", idx),
					Value: fmt.Sprintf("val-%d", idx),
				}
				return tx.Create(&item).Error
			})
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent transaction failed: %v", err)
	}

	var total int64
	db.Model(&StressItem{}).Where("key LIKE 'concurrent-%'").Count(&total)
	if total != goroutines {
		t.Fatalf("expected %d committed rows, found %d", goroutines, total)
	}
}
