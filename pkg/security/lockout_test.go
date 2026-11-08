package security

import (
	"context"
	"testing"
)

func TestLockout_InMemoryFallback(t *testing.T) {
	ctx := context.Background()
	key := "test-user@example.com"

	// Ensure clean start
	_ = ResetFailedAttempts(ctx, nil, key)

	// Initial check: should be allowed
	res, err := CheckLockout(ctx, nil, key)
	if err != nil {
		t.Fatalf("unexpected error on CheckLockout: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed=true initially, got false")
	}

	// Record 4 failed attempts: should not be locked yet
	for i := 1; i <= 4; i++ {
		rem, locked, err := RecordFailedAttempt(ctx, nil, key)
		if err != nil {
			t.Fatalf("failed recording attempt %d: %v", i, err)
		}
		if locked {
			t.Fatalf("unexpected lock at attempt %d", i)
		}
		if rem != MaxFailedAttempts-i {
			t.Fatalf("expected %d remaining, got %d", MaxFailedAttempts-i, rem)
		}
	}

	// 5th failed attempt: should trigger lockout
	rem, locked, err := RecordFailedAttempt(ctx, nil, key)
	if err != nil {
		t.Fatalf("failed recording 5th attempt: %v", err)
	}
	if !locked {
		t.Fatalf("expected locked=true at 5th attempt")
	}
	if rem != 0 {
		t.Fatalf("expected 0 remaining, got %d", rem)
	}

	// CheckLockout should now report disallowed
	res, err = CheckLockout(ctx, nil, key)
	if err != nil {
		t.Fatalf("unexpected error on CheckLockout: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected allowed=false after 5 failures")
	}
	if res.RetryAfter <= 0 {
		t.Fatalf("expected positive RetryAfter, got %d", res.RetryAfter)
	}

	// Reset attempts
	err = ResetFailedAttempts(ctx, nil, key)
	if err != nil {
		t.Fatalf("unexpected error on ResetFailedAttempts: %v", err)
	}

	// CheckLockout should be allowed again
	res, err = CheckLockout(ctx, nil, key)
	if err != nil {
		t.Fatalf("unexpected error on CheckLockout: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed=true after reset")
	}
}
