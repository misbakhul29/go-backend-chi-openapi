package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAdversarial_Config_MissingFiles tests that LoadEnv gracefully handles all variations
// of missing files without panicking or failing to populate default values.
func TestAdversarial_Config_MissingFiles(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	missingCases := []struct {
		name  string
		files []string
	}{
		{"no arguments provided", nil},
		{"empty string filename", []string{""}},
		{"non-existent relative file", []string{"missing_file_xyz_123.env"}},
		{"non-existent absolute path", []string{"/tmp/definitely_absent_env_file_987654.env"}},
		{"deeply nested non-existent directory", []string{"/tmp/a/b/c/d/e/f/g/missing.env"}},
		{"multiple non-existent files", []string{"none1.env", "none2.env", "none3.env"}},
		{"mixture of empty and missing files", []string{"", "none.env", ""}},
	}

	for _, tc := range missingCases {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			oldLogOutput := log.Writer()
			log.SetOutput(&logBuf)
			defer log.SetOutput(oldLogOutput)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[VULNERABILITY] LoadEnv panicked on missing file case %s: %v", tc.name, r)
				}
			}()

			cfg := LoadEnv(tc.files...)
			if cfg == nil {
				t.Fatalf("[VULNERABILITY] LoadEnv returned nil for case %s", tc.name)
			}

			// Ensure missing files do NOT emit spurious error warnings
			if strings.Contains(logBuf.String(), "warning: error loading .env file") {
				t.Errorf("[DEFECT] LoadEnv emitted warning for missing file in case %s: %s", tc.name, logBuf.String())
			}

			// Invariant checks on default fallbacks
			if cfg.APPName != "Backend Framework" {
				t.Errorf("expected default APPName, got %q", cfg.APPName)
			}
			if cfg.Database.Hostname != "localhost" {
				t.Errorf("expected default DB Hostname, got %q", cfg.Database.Hostname)
			}
			if cfg.RabbitMQ.Hostname != "localhost" {
				t.Errorf("expected default RabbitMQ Hostname, got %q", cfg.RabbitMQ.Hostname)
			}
		})
	}
}

// TestAdversarial_Config_InvalidSyntax tests that files with broken syntax,
// unclosed quotes, and corrupt binary bytes emit diagnostic warnings and do not crash.
func TestAdversarial_Config_InvalidSyntax(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	tempDir := t.TempDir()

	syntaxCases := []struct {
		name    string
		content []byte
	}{
		{
			name:    "no equals sign plain text",
			content: []byte("THIS IS PLAIN TEXT WITHOUT ANY KEY VALUE PAIRS\nSECOND LINE OF NONSENSE"),
		},
		{
			name:    "unclosed double quote",
			content: []byte("APP_NAME=\"unclosed double quote string\nPORT=8080"),
		},
		{
			name:    "unclosed single quote",
			content: []byte("APP_NAME='unclosed single quote string\nPORT=8080"),
		},
		{
			name:    "corrupted binary bytes",
			content: []byte{0x00, 0xff, 0xfe, 0x01, 0x02, 0x80, 0x7f, 0x55, 0xaa},
		},
		{
			name:    "broken export keyword",
			content: []byte("export BROKEN_NO_EQUALS\nexport SECOND_BROKEN"),
		},
		{
			name:    "malformed multiline with special characters",
			content: []byte("KEY=\"line 1\nline 2\x00broken"),
		},
	}

	for _, tc := range syntaxCases {
		t.Run(tc.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, strings.ReplaceAll(tc.name, " ", "_")+".env")
			if err := os.WriteFile(filePath, tc.content, 0644); err != nil {
				t.Fatalf("failed to write test fixture: %v", err)
			}

			var logBuf bytes.Buffer
			oldLogOutput := log.Writer()
			log.SetOutput(&logBuf)
			defer log.SetOutput(oldLogOutput)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("[VULNERABILITY] LoadEnv panicked on invalid syntax %s: %v", tc.name, r)
				}
			}()

			cfg := LoadEnv(filePath)
			if cfg == nil {
				t.Fatalf("[VULNERABILITY] LoadEnv returned nil for syntax case %s", tc.name)
			}

			// Genuine syntax errors must be diagnosed via warning log
			loggedOutput := logBuf.String()
			if !strings.Contains(loggedOutput, "warning: error loading .env file") {
				t.Errorf("[DEFECT] Expected warning logged for invalid syntax in %s, got: %q", tc.name, loggedOutput)
			}
		})
	}
}

// TestAdversarial_Config_PermissionErrors tests file permission denial scenarios.
func TestAdversarial_Config_PermissionErrors(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission error test when running as root (UID 0 bypasses 0000 permissions)")
	}

	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	tempDir := t.TempDir()
	unreadableFile := filepath.Join(tempDir, "unreadable.env")

	if err := os.WriteFile(unreadableFile, []byte("APP_NAME=SecretApp\nPORT=9090"), 0000); err != nil {
		t.Fatalf("failed to create 0000 file: %v", err)
	}

	var logBuf bytes.Buffer
	oldLogOutput := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldLogOutput)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("[VULNERABILITY] LoadEnv panicked on permission denied file: %v", r)
		}
	}()

	cfg := LoadEnv(unreadableFile)
	if cfg == nil {
		t.Fatalf("[VULNERABILITY] LoadEnv returned nil for permission denied file")
	}

	loggedOutput := logBuf.String()
	if !strings.Contains(loggedOutput, "warning: error loading .env file") {
		t.Errorf("[DEFECT] Expected warning logged for permission denied file, got: %q", loggedOutput)
	}
	if !strings.Contains(loggedOutput, "permission denied") {
		t.Errorf("[DEFECT] Expected 'permission denied' in warning log, got: %q", loggedOutput)
	}
}

// TestAdversarial_Config_DirectoryAsEnvFile tests passing a directory instead of a regular file.
func TestAdversarial_Config_DirectoryAsEnvFile(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	tempDir := t.TempDir()

	var logBuf bytes.Buffer
	oldLogOutput := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldLogOutput)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("[VULNERABILITY] LoadEnv panicked when directory passed as .env file: %v", r)
		}
	}()

	cfg := LoadEnv(tempDir)
	if cfg == nil {
		t.Fatalf("[VULNERABILITY] LoadEnv returned nil when directory passed as .env file")
	}

	loggedOutput := logBuf.String()
	if !strings.Contains(loggedOutput, "warning: error loading .env file") {
		t.Errorf("[DEFECT] Expected warning logged when passing directory, got: %q", loggedOutput)
	}
}

// TestAdversarial_Config_SpecialDeviceFiles tests handling of /dev/null and empty files.
func TestAdversarial_Config_SpecialDeviceFiles(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	if _, err := os.Stat("/dev/null"); err == nil {
		var logBuf bytes.Buffer
		oldLogOutput := log.Writer()
		log.SetOutput(&logBuf)
		defer log.SetOutput(oldLogOutput)

		cfg := LoadEnv("/dev/null")
		if cfg == nil {
			t.Fatalf("expected non-nil config for /dev/null")
		}
		if logBuf.Len() > 0 {
			t.Errorf("expected no warning for /dev/null, got: %s", logBuf.String())
		}
	}
}
