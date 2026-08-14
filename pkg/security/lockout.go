package security

import (
	"context"

	"github.com/misbakhul29/backend-framework/pkg/redisx"
	"github.com/redis/go-redis/v9"
)

type LockoutResult struct {
	Allowed    bool
	RetryAfter int // in seconds
}

func CheckLockout(ctx context.Context, rdb *redis.Client, key string) (*LockoutResult, error) {
	if rdb == nil {
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
		return &LockoutResult{Allowed: false, RetryAfter: int(ttl.Seconds())}, nil
	}

	return &LockoutResult{Allowed: true, RetryAfter: 0}, nil
}
