package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEnvConfig_SingleSourceOfTruth(t *testing.T) {
	src, err := findSourceEnvFile("")
	if err != nil {
		t.Fatalf("findSourceEnvFile failed: %v", err)
	}

	items, err := parseEnvConfig(src)
	if err != nil {
		t.Fatalf("parseEnvConfig failed on %s: %v", src, err)
	}

	if len(items) == 0 {
		t.Fatalf("expected extracted items from %s, got 0", src)
	}

	itemMap := make(map[string]EnvItem)
	for _, it := range items {
		itemMap[it.Key] = it
	}

	// Verify required variables
	expectedMandatory := []string{
		"DB_HOST", "DB_PORT", "DB_NAME", "DB_USER",
		"REDIS_HOST", "REDIS_PORT", "RABBITMQ_HOST", "RABBITMQ_PORT",
		"JWT_SECRET", "ENCRYPTION_KEY",
	}

	for _, k := range expectedMandatory {
		it, ok := itemMap[k]
		if !ok {
			t.Errorf("expected key %s to be parsed from env.go", k)
			continue
		}
		if !it.Required {
			t.Errorf("expected key %s to be marked Required", k)
		}
	}

	// Verify OAuth and SAML keys were dynamically parsed
	oauthKeys := []string{
		"GOOGLE_CLIENT_ID", "GITHUB_CLIENT_ID", "APPLE_CLIENT_ID",
		"SAML_SP_ENTITY_ID",
	}

	for _, k := range oauthKeys {
		if _, ok := itemMap[k]; !ok {
			t.Errorf("expected OAuth/SAML key %s to be parsed from env.go", k)
		}
	}

	// Verify content output format
	content := generateEnvContent(items, src)
	if !strings.Contains(content, "Auto-generated from") {
		t.Errorf("expected header notice in generated content")
	}
	if !strings.Contains(content, "DB_HOST=localhost") {
		t.Errorf("expected DB_HOST=localhost in generated content")
	}
}

func TestWriteEnvFile(t *testing.T) {
	tempDir := t.TempDir()
	envPath := filepath.Join(tempDir, ".env")
	testContent := "TEST_KEY=test_value\n"

	if err := writeEnvFile(envPath, testContent, false); err != nil {
		t.Fatalf("failed to write initial env file: %v", err)
	}

	data, err := os.ReadFile(envPath)
	if err != nil || string(data) != testContent {
		t.Fatalf("unexpected content read from env file: %s", string(data))
	}

	// Overwrite without force should fail
	if err := writeEnvFile(envPath, "NEW_KEY=val\n", false); err == nil {
		t.Errorf("expected error when overwriting without force")
	}

	// Overwrite with force should succeed
	if err := writeEnvFile(envPath, "NEW_KEY=val\n", true); err != nil {
		t.Errorf("expected success with force overwrite, got %v", err)
	}
}
