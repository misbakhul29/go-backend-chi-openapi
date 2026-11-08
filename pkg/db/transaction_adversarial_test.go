package db

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/misbakhul29/backend-framework/config"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// AdversarialItem for testing WithTx behaviors
type AdversarialItem struct {
	ID        uint   `gorm:"primaryKey"`
	Key       string `gorm:"type:varchar(100);uniqueIndex"`
	Val       string `gorm:"type:varchar(255)"`
	CreatedAt time.Time
}

func setupAdversarialDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:mem_%s?mode=memory&cache=shared&_busy_timeout=5000", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0)
	}
	if err := db.AutoMigrate(&AdversarialItem{}); err != nil {
		t.Fatalf("failed to automigrate AdversarialItem: %v", err)
	}
	db.Exec("DELETE FROM adversarial_items")
	return db
}

// 1. isPostgresDialect Exhaustive Matrix
func TestAdversarial_IsPostgresDialect_Matrix(t *testing.T) {
	cases := []struct {
		name     string
		input    *gorm.DB
		expected bool
	}{
		{"nil pointer", nil, false},
		{"uninitialized &gorm.DB{}", &gorm.DB{}, false},
		{"&gorm.DB with empty Config", &gorm.DB{Config: &gorm.Config{}}, false},
		{"&gorm.DB with SQLite dialector", &gorm.DB{Config: &gorm.Config{Dialector: sqlite.Open("file::memory:")}}, false},
		{"&gorm.DB with Postgres dialector", &gorm.DB{Config: &gorm.Config{Dialector: postgres.New(postgres.Config{})}}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := isPostgresDialect(tc.input)
			if res != tc.expected {
				t.Errorf("expected isPostgresDialect = %v, got %v for %s", tc.expected, res, tc.name)
			}
		})
	}
}

// 2. WithTx Nil DB and Nil Callback Variations
func TestAdversarial_WithTx_NilGuards_Deep(t *testing.T) {
	ctx := context.Background()
	db := setupAdversarialDB(t)

	// nil DB, valid callback
	err := WithTx(ctx, nil, func(txCtx context.Context, tx *gorm.DB) error {
		return nil
	})
	if !errors.Is(err, ErrNilDB) {
		t.Errorf("expected ErrNilDB for nil db, got %v", err)
	}

	// valid DB, nil callback
	err = WithTx(ctx, db, nil)
	if !errors.Is(err, ErrNilTxFunc) {
		t.Errorf("expected ErrNilTxFunc for nil callback, got %v", err)
	}

	// nil DB, nil callback
	err = WithTx(ctx, nil, nil)
	if !errors.Is(err, ErrNilTxFunc) {
		t.Errorf("expected ErrNilTxFunc when both nil, got %v", err)
	}

	// context has active tx, but fn is nil
	ctxWithTx := context.WithValue(ctx, TxContextKey, db)
	err = WithTx(ctxWithTx, db, nil)
	if !errors.Is(err, ErrNilTxFunc) {
		t.Errorf("expected ErrNilTxFunc even with active tx in context, got %v", err)
	}

	// context has active tx, and db is nil -> should succeed because existing tx is used
	err = WithTx(ctxWithTx, nil, func(txCtx context.Context, tx *gorm.DB) error {
		if tx != db {
			t.Errorf("expected tx to match db from context")
		}
		return nil
	})
	if err != nil {
		t.Errorf("expected success when existingTx is in context even if db is nil, got %v", err)
	}
}

// 3. WithTx with Uninitialized gorm.DB (nil Config)
func TestAdversarial_WithTx_UninitializedDB(t *testing.T) {
	ctx := context.Background()
	uninitializedDB := &gorm.DB{}

	defer func() {
		if r := recover(); r != nil {
			t.Logf("[OBSERVED PANIC] WithTx with &gorm.DB{} triggered panic: %v", r)
		}
	}()

	err := WithTx(ctx, uninitializedDB, func(txCtx context.Context, tx *gorm.DB) error {
		return nil
	})
	t.Logf("WithTx(&gorm.DB{}) returned err: %v", err)
}

// 4. Nested Transactions (3-tier depth) and Error Propagation
func TestAdversarial_WithTx_DeeplyNestedTransactions(t *testing.T) {
	db := setupAdversarialDB(t)
	ctx := context.Background()

	var txTier1, txTier2, txTier3 *gorm.DB

	err := WithTx(ctx, db, func(ctx1 context.Context, tx1 *gorm.DB) error {
		txTier1 = tx1
		if err := tx1.Create(&AdversarialItem{Key: "t1", Val: "v1"}).Error; err != nil {
			return err
		}

		return WithTx(ctx1, db, func(ctx2 context.Context, tx2 *gorm.DB) error {
			txTier2 = tx2
			if err := tx2.Create(&AdversarialItem{Key: "t2", Val: "v2"}).Error; err != nil {
				return err
			}

			return WithTx(ctx2, db, func(ctx3 context.Context, tx3 *gorm.DB) error {
				txTier3 = tx3
				return tx3.Create(&AdversarialItem{Key: "t3", Val: "v3"}).Error
			})
		})
	})

	if err != nil {
		t.Fatalf("unexpected error in nested transactions: %v", err)
	}

	// Verify all 3 tiers received the exact same transaction instance
	if txTier1 != txTier2 || txTier2 != txTier3 {
		t.Errorf("expected all tiers to reuse same tx instance: t1=%p, t2=%p, t3=%p", txTier1, txTier2, txTier3)
	}

	// Verify all 3 items committed
	var count int64
	db.Model(&AdversarialItem{}).Where("key IN ('t1', 't2', 't3')").Count(&count)
	if count != 3 {
		t.Errorf("expected 3 committed rows, got %d", count)
	}
}

// 5. Deeply Nested Rollback: Inner failure rolls back entire outer transaction
func TestAdversarial_WithTx_NestedRollback(t *testing.T) {
	db := setupAdversarialDB(t)
	ctx := context.Background()

	innerErr := errors.New("aborted deeply inside tier 3")

	err := WithTx(ctx, db, func(ctx1 context.Context, tx1 *gorm.DB) error {
		if err := tx1.Create(&AdversarialItem{Key: "rollback-t1", Val: "v1"}).Error; err != nil {
			return err
		}

		return WithTx(ctx1, db, func(ctx2 context.Context, tx2 *gorm.DB) error {
			if err := tx2.Create(&AdversarialItem{Key: "rollback-t2", Val: "v2"}).Error; err != nil {
				return err
			}

			return WithTx(ctx2, db, func(ctx3 context.Context, tx3 *gorm.DB) error {
				if err := tx3.Create(&AdversarialItem{Key: "rollback-t3", Val: "v3"}).Error; err != nil {
					return err
				}
				return innerErr
			})
		})
	})

	if !errors.Is(err, innerErr) {
		t.Fatalf("expected innerErr, got %v", err)
	}

	// Verify ZERO items committed across all 3 tiers
	var count int64
	db.Model(&AdversarialItem{}).Where("key LIKE 'rollback-t%'").Count(&count)
	if count != 0 {
		t.Fatalf("LEAKED ROWS DETECTED! Expected 0 rows committed after nested rollback, found %d", count)
	}
}

// 6. Context Cancellation Before WithTx
func TestAdversarial_WithTx_ContextCancelledBefore(t *testing.T) {
	db := setupAdversarialDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before transaction starts

	var callbackRan bool
	err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
		callbackRan = true
		return tx.Create(&AdversarialItem{Key: "cancelled-pre", Val: "val"}).Error
	})

	if callbackRan {
		t.Errorf("expected callback not to run when context is cancelled before transaction start")
	}

	if err == nil {
		t.Errorf("expected error when context is pre-cancelled, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Logf("WithTx returned error for pre-cancelled context: %v (errors.Is(context.Canceled)=%v)", err, errors.Is(err, context.Canceled))
	}

	var count int64
	db.Model(&AdversarialItem{}).Where("key = ?", "cancelled-pre").Count(&count)
	if count != 0 {
		t.Errorf("expected 0 rows committed when context is cancelled, found %d", count)
	}
}

// 6b. Context Deadline Exceeded Before WithTx
func TestAdversarial_WithTx_ContextDeadlineExceededBefore(t *testing.T) {
	db := setupAdversarialDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // Ensure timeout expires

	var callbackRan bool
	err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
		callbackRan = true
		return tx.Create(&AdversarialItem{Key: "timeout-pre", Val: "val"}).Error
	})

	if callbackRan {
		t.Errorf("expected callback not to run when context is timed out")
	}

	if err == nil {
		t.Errorf("expected error when context is timed out, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("WithTx returned error for timed-out context: %v", err)
	}

	var count int64
	db.Model(&AdversarialItem{}).Where("key = ?", "timeout-pre").Count(&count)
	if count != 0 {
		t.Errorf("expected 0 rows committed when context timed out, found %d", count)
	}
}

// 7. Context Cancellation During WithTx Callback
func TestAdversarial_WithTx_ContextCancelledDuringCallback(t *testing.T) {
	db := setupAdversarialDB(t)
	ctx, cancel := context.WithCancel(context.Background())

	err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
		if err := tx.Create(&AdversarialItem{Key: "mid-cancel-1", Val: "val1"}).Error; err != nil {
			return err
		}

		// Cancel context mid-execution
		cancel()

		// Attempt query with cancelled context
		return tx.WithContext(txCtx).Create(&AdversarialItem{Key: "mid-cancel-2", Val: "val2"}).Error
	})

	if err == nil {
		t.Errorf("expected error when context is cancelled during callback, got nil")
	}

	var count int64
	db.Model(&AdversarialItem{}).Where("key LIKE 'mid-cancel-%'").Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 rows committed after context cancellation rollback, found %d", count)
	}
}

// 8. Panic Inside Nested Transaction Rolled Back Cleanly
func TestAdversarial_WithTx_NestedPanicRollback(t *testing.T) {
	db := setupAdversarialDB(t)
	ctx := context.Background()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected nested panic to bubble up")
			}
		}()

		_ = WithTx(ctx, db, func(ctx1 context.Context, tx1 *gorm.DB) error {
			if err := tx1.Create(&AdversarialItem{Key: "panic-nested-1", Val: "val"}).Error; err != nil {
				return err
			}
			return WithTx(ctx1, db, func(ctx2 context.Context, tx2 *gorm.DB) error {
				if err := tx2.Create(&AdversarialItem{Key: "panic-nested-2", Val: "val"}).Error; err != nil {
					return err
				}
				panic("simulated critical crash inside inner transaction")
			})
		})
	}()

	var count int64
	db.Model(&AdversarialItem{}).Where("key LIKE 'panic-nested-%'").Count(&count)
	if count != 0 {
		t.Fatalf("expected 0 rows committed after nested panic rollback, found %d", count)
	}
}

// 9. High-Concurrency Stress Test with Race Detector
func TestAdversarial_WithTx_HighConcurrency(t *testing.T) {
	db := setupAdversarialDB(t)

	const goroutines = 30
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()
			err := WithTx(ctx, db, func(txCtx context.Context, tx *gorm.DB) error {
				item := AdversarialItem{
					Key: fmt.Sprintf("high-conc-%d", idx),
					Val: fmt.Sprintf("val-%d", idx),
				}
				if err := tx.Create(&item).Error; err != nil {
					return err
				}

				// nested read
				return WithTx(txCtx, db, func(innerCtx context.Context, innerTx *gorm.DB) error {
					var found AdversarialItem
					return innerTx.First(&found, "key = ?", item.Key).Error
				})
			})
			if err != nil {
				errCh <- fmt.Errorf("goroutine %d failed: %w", idx, err)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent transaction error: %v", err)
	}

	var count int64
	db.Model(&AdversarialItem{}).Where("key LIKE 'high-conc-%'").Count(&count)
	if count != goroutines {
		t.Errorf("expected %d committed rows, found %d", goroutines, count)
	}
}

// 10. Multi-Tenant and UserID Context Preservation Across Nested WithTx
func TestAdversarial_WithTx_ContextValuePreservation(t *testing.T) {
	db := setupAdversarialDB(t)

	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()

	config.Cfg = &config.Env{
		Database: config.Database{
			EnableMultiTenant: true,
		},
	}

	ctx := context.Background()
	ctx = WithTenantID(ctx, "tenant-matrix-007")
	ctx = WithUserID(ctx, "user-matrix-42")

	var tier1Tenant, tier2Tenant string
	var tier1User, tier2User string

	err := WithTx(ctx, db, func(ctx1 context.Context, tx1 *gorm.DB) error {
		tier1Tenant = GetTenantID(ctx1)
		tier1User = GetUserID(ctx1)

		return WithTx(ctx1, db, func(ctx2 context.Context, tx2 *gorm.DB) error {
			tier2Tenant = GetTenantID(ctx2)
			tier2User = GetUserID(ctx2)
			return nil
		})
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tier1Tenant != "tenant-matrix-007" || tier2Tenant != "tenant-matrix-007" {
		t.Errorf("tenant ID lost across tiers: tier1=%s, tier2=%s", tier1Tenant, tier2Tenant)
	}
	if tier1User != "user-matrix-42" || tier2User != "user-matrix-42" {
		t.Errorf("user ID lost across tiers: tier1=%s, tier2=%s", tier1User, tier2User)
	}
}
