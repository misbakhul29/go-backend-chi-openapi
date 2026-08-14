package observer

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestStructuredLogger(t *testing.T) {
	// Set up a custom buffer to capture log output
	var buf bytes.Buffer
	
	// Create replaceAttr function same as the one in logger.go
	piiKeys := map[string]bool{
		"password":      true,
		"passwd":        true,
		"token":         true,
		"access_token":  true,
		"refresh_token": true,
		"secret":        true,
		"ssn":           true,
		"tax_id":        true,
		"pin":           true,
		"credit_card":   true,
		"cc":            true,
		"cvv":           true,
		"authorization": true,
		"email":         true,
	}

	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		keyLower := strings.ToLower(a.Key)
		if piiKeys[keyLower] || strings.Contains(keyLower, "password") || strings.Contains(keyLower, "secret") || strings.Contains(keyLower, "token") {
			return slog.String(a.Key, "[REDACTED]")
		}
		return a
	}

	jsonHandler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: replaceAttr,
	})

	testLogger := slog.New(&ContextHandler{Handler: jsonHandler})

	// 1. Test context extraction
	ctx := context.Background()
	ctx = context.WithValue(ctx, TraceIDKey, "test-trace-id-123")
	ctx = context.WithValue(ctx, RequestIDKey, "test-request-id-456")
	ctx = context.WithValue(ctx, TenantIDKey, "test-tenant-789")
	ctx = context.WithValue(ctx, UserIDKey, "test-user-000")

	testLogger.InfoContext(ctx, "hello test log", slog.String("password", "super-secret-pass"), slog.String("normal_field", "normal_value"))

	// Parse JSON output
	var logMap map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logMap)
	if err != nil {
		t.Fatalf("Failed to parse log JSON: %v", err)
	}

	// Verify context values are present in log
	if logMap["trace_id"] != "test-trace-id-123" {
		t.Errorf("Expected trace_id 'test-trace-id-123', got %v", logMap["trace_id"])
	}
	if logMap["request_id"] != "test-request-id-456" {
		t.Errorf("Expected request_id 'test-request-id-456', got %v", logMap["request_id"])
	}
	if logMap["tenant_id"] != "test-tenant-789" {
		t.Errorf("Expected tenant_id 'test-tenant-789', got %v", logMap["tenant_id"])
	}
	if logMap["user_id"] != "test-user-000" {
		t.Errorf("Expected user_id 'test-user-000', got %v", logMap["user_id"])
	}

	// Verify normal field remains unchanged
	if logMap["normal_field"] != "normal_value" {
		t.Errorf("Expected normal_field 'normal_value', got %v", logMap["normal_field"])
	}

	// Verify PII field is redacted
	if logMap["password"] != "[REDACTED]" {
		t.Errorf("Expected password to be '[REDACTED]', got %v", logMap["password"])
	}
}
