package audit

import (
	"context"
	"net/http/httptest"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/misbakhul29/backend-framework/pkg/db/models"
)

func TestAuditService_LogAndPIIMasking(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}

	if err := db.AutoMigrate(&models.AuditLog{}); err != nil {
		t.Fatalf("failed to migrate audit log: %v", err)
	}

	svc := NewService(db, nil)
	userID := "u-12345"

	err = svc.Log(context.Background(), Event{
		EventType: EventLoginSuccess,
		Status:    "SUCCESS",
		UserID:    &userID,
		Metadata: map[string]any{
			"email":    "user@example.com",
			"password": "SuperSecretPassword123", // Should be redacted!
			"secret":   "totpSecretKey",          // Should be redacted!
			"browser":  "Chrome",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error logging event: %v", err)
	}

	var count int64
	db.Model(&models.AuditLog{}).Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 audit record, got %d", count)
	}

	var record models.AuditLog
	db.First(&record)
	if record.EventType != EventLoginSuccess || *record.UserID != "u-12345" {
		t.Fatalf("unexpected audit log record: %+v", record)
	}

	if record.Metadata == nil || *record.Metadata == "" {
		t.Fatal("expected metadata to be saved")
	}

	// Verify PII masking
	metaStr := *record.Metadata
	if !containsString(metaStr, "[REDACTED]") {
		t.Fatalf("expected password to be redacted in metadata: %s", metaStr)
	}
}

func TestEventFromRequest(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	uid := "uid-99"
	ev := EventFromRequest(req, EventLoginSuccess, "SUCCESS", &uid, map[string]any{"action": "test"})

	if *ev.IPAddress != "203.0.113.195" {
		t.Fatalf("expected client IP 203.0.113.195, got %s", *ev.IPAddress)
	}
	if *ev.UserAgent != "Mozilla/5.0" {
		t.Fatalf("expected User-Agent Mozilla/5.0, got %s", *ev.UserAgent)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
