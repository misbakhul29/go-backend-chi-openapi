package redisx

import (
	"context"
	"fmt"
	"time"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	"github.com/redis/go-redis/v9"
)

// InitRedis initializes and pings a go-redis client.
func InitRedis(cfg config.Redis) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Hostname, cfg.Port),
		Password: cfg.Password,
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		observer.Log.Error("failed to connect to Redis", "error", err)
		return nil, err
	}

	observer.Log.Info("Redis connection established successfully")
	return client, nil
}
