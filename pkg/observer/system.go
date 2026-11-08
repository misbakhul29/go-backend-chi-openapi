package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

var serverStartTime = time.Now()

type MemoryStats struct {
	AllocMB      float64 `json:"alloc_mb"`
	TotalAllocMB float64 `json:"total_alloc_mb"`
	SysMB        float64 `json:"sys_mb"`
	HeapAllocMB  float64 `json:"heap_alloc_mb"`
	HeapInuseMB  float64 `json:"heap_inuse_mb"`
	NumGC        uint32  `json:"num_gc"`
}

type CPUStats struct {
	NumCPU       int `json:"num_cpu"`
	NumGoroutine int `json:"num_goroutine"`
}

type DBPoolStats struct {
	OpenConnections int `json:"open_connections"`
	InUse           int `json:"in_use"`
	Idle            int `json:"idle"`
}

type DependencyStatus struct {
	Database string       `json:"database"`
	DBPool   *DBPoolStats `json:"db_pool,omitempty"`
	Redis    string       `json:"redis"`
	RabbitMQ string       `json:"rabbitmq"`
}

type SystemDiagnostics struct {
	Status       string           `json:"status"`
	Uptime       string           `json:"uptime"`
	UptimeSec    int64            `json:"uptime_seconds"`
	Timestamp    time.Time        `json:"timestamp"`
	GoVersion    string           `json:"go_version"`
	Memory       MemoryStats      `json:"memory"`
	CPU          CPUStats         `json:"cpu"`
	Dependencies DependencyStatus `json:"dependencies"`
}

func CollectSystemDiagnostics(ctx context.Context, db *gorm.DB, rdb *redis.Client, rmq *amqp091.Connection) SystemDiagnostics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	toMB := func(b uint64) float64 {
		return float64(b) / 1024 / 1024
	}

	depStatus := DependencyStatus{
		Database: "disconnected",
		Redis:    "disconnected",
		RabbitMQ: "disconnected",
	}

	allHealthy := true

	if db != nil {
		sqlDB, err := db.DB()
		if err == nil {
			if err := sqlDB.PingContext(ctx); err == nil {
				depStatus.Database = "connected"
				stats := sqlDB.Stats()
				depStatus.DBPool = &DBPoolStats{
					OpenConnections: stats.OpenConnections,
					InUse:           stats.InUse,
					Idle:            stats.Idle,
				}
			} else {
				allHealthy = false
				depStatus.Database = fmt.Sprintf("error: %v", err)
			}
		}
	}

	if rdb != nil {
		if err := rdb.Ping(ctx).Err(); err == nil {
			depStatus.Redis = "connected"
		} else {
			allHealthy = false
			depStatus.Redis = fmt.Sprintf("error: %v", err)
		}
	}

	if rmq != nil {
		if !rmq.IsClosed() {
			depStatus.RabbitMQ = "connected"
		} else {
			allHealthy = false
			depStatus.RabbitMQ = "closed"
		}
	}

	status := "healthy"
	if !allHealthy {
		status = "degraded"
	}

	uptimeDuration := time.Since(serverStartTime)

	return SystemDiagnostics{
		Status:    status,
		Uptime:    uptimeDuration.Truncate(time.Second).String(),
		UptimeSec: int64(uptimeDuration.Seconds()),
		Timestamp: time.Now().UTC(),
		GoVersion: runtime.Version(),
		Memory: MemoryStats{
			AllocMB:      float64(int(toMB(m.Alloc)*100)) / 100,
			TotalAllocMB: float64(int(toMB(m.TotalAlloc)*100)) / 100,
			SysMB:        float64(int(toMB(m.Sys)*100)) / 100,
			HeapAllocMB:  float64(int(toMB(m.HeapAlloc)*100)) / 100,
			HeapInuseMB:  float64(int(toMB(m.HeapInuse)*100)) / 100,
			NumGC:        m.NumGC,
		},
		CPU: CPUStats{
			NumCPU:       runtime.NumCPU(),
			NumGoroutine: runtime.NumGoroutine(),
		},
		Dependencies: depStatus,
	}
}

func SystemDiagnosticsHandler(db *gorm.DB, rdb *redis.Client, rmq *amqp091.Connection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		diag := CollectSystemDiagnostics(r.Context(), db, rdb, rmq)
		w.Header().Set("Content-Type", "application/json")
		if diag.Status != "healthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		json.NewEncoder(w).Encode(diag)
	}
}

