package redisx

import "fmt"

var (
	LockKey = func(key string) string { return fmt.Sprintf("lock:%s", key) }
)
