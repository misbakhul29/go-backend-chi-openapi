package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/misbakhul29/backend-framework/pkg/redisx"
	"github.com/redis/go-redis/v9"
)

const (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
)

type LockoutResult struct {
	Allowed    bool
	RetryAfter int // in seconds
}

type memoryLockoutEntry struct {
	attempts    int
	windowStart time.Time
	lockedUntil time.Time
}

var (
	memLockoutMu sync.RWMutex
	memLockouts  = make(map[string]*memoryLockoutEntry)
)

func CheckLockout(ctx context.Context, rdb *redis.Client, key string) (*LockoutResult, error) {
	if rdb == nil {
		memLockoutMu.RLock()
		entry, exists := memLockouts[key]
		memLockoutMu.RUnlock()

		if !exists {
			return &LockoutResult{Allowed: true, RetryAfter: 0}, nil
		}

		now := time.Now()
		if now.Before(entry.lockedUntil) {
			retryAfter := int(time.Until(entry.lockedUntil).Seconds())
			if retryAfter <= 0 {
				retryAfter = 1
			}
			return &LockoutResult{Allowed: false, RetryAfter: retryAfter}, nil
		}

		return &LockoutResult{Allowed: true, RetryAfter: 0}, nil
	}

	lockKey := redisx.LockKey(key)
	exists, err := rdb.Exists(ctx, lockKey).Result()
	if err != nil {
		return nil, err
	}
	if exists > 0 {
		ttl, err := rdb.TTL(ctx, lockKey).Result()
		if err != nil {
			return nil, err
		}
		retryAfter := int(ttl.Seconds())
		if retryAfter <= 0 {
			retryAfter = 1
		}
		return &LockoutResult{Allowed: false, RetryAfter: retryAfter}, nil
	}

	return &LockoutResult{Allowed: true, RetryAfter: 0}, nil
}

// RecordFailedAttempt tracks consecutive authentication failures and enforces lockout upon reaching threshold.
func RecordFailedAttempt(ctx context.Context, rdb *redis.Client, key string) (remaining int, locked bool, err error) {
	if rdb == nil {
		memLockoutMu.Lock()
		defer memLockoutMu.Unlock()

		now := time.Now()
		entry, exists := memLockouts[key]
		if !exists || now.Sub(entry.windowStart) > LockoutDuration {
			entry = &memoryLockoutEntry{
				attempts:    0,
				windowStart: now,
			}
			memLockouts[key] = entry
		}

		entry.attempts++
		if entry.attempts >= MaxFailedAttempts {
			entry.lockedUntil = now.Add(LockoutDuration)
			return 0, true, nil
		}

		rem := MaxFailedAttempts - entry.attempts
		return rem, false, nil
	}

	attemptsKey := fmt.Sprintf("attempts:%s", key)
	lockKey := redisx.LockKey(key)

	count, err := rdb.Incr(ctx, attemptsKey).Result()
	if err != nil {
		return 0, false, err
	}

	if count == 1 {
		_ = rdb.Expire(ctx, attemptsKey, LockoutDuration).Err()
	}

	if count >= MaxFailedAttempts {
		_ = rdb.Set(ctx, lockKey, "locked", LockoutDuration).Err()
		return 0, true, nil
	}

	rem := MaxFailedAttempts - int(count)
	if rem < 0 {
		rem = 0
	}
	return rem, false, nil
}

// ResetFailedAttempts clears failed attempt counters and active lockouts for a key.
func ResetFailedAttempts(ctx context.Context, rdb *redis.Client, key string) error {
	if rdb == nil {
		memLockoutMu.Lock()
		delete(memLockouts, key)
		memLockoutMu.Unlock()
		return nil
	}

	attemptsKey := fmt.Sprintf("attempts:%s", key)
	lockKey := redisx.LockKey(key)
	return rdb.Del(ctx, attemptsKey, lockKey).Err()
}
