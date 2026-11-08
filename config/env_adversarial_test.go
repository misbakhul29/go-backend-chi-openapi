package config

import (
	"fmt"
	"os"
	"sync"
	"testing"
)

// TestAdversarial_LoadEnv_MissingFileScenarios empirically verifies that LoadEnv
// tolerates completely absent .env files, empty file paths, and multiple non-existent paths
// without panicking when NODE_ENV is test.
func TestAdversarial_LoadEnv_MissingFileScenarios(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	missingFileScenarios := []struct {
		name  string
		files []string
	}{
		{"no arguments (default .env absent)", nil},
		{"empty string path", []string{""}},
		{"explicit non-existent path", []string{"/path/to/definitely/nonexistent.env"}},
		{"multiple non-existent paths", []string{"missing1.env", "missing2.env", "missing3.env"}},
		{"relative non-existent nested", []string{"./nested/dir/does_not_exist.env"}},
	}

	for _, sc := range missingFileScenarios {
		t.Run(sc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("LoadEnv panicked on %s: %v", sc.name, r)
				}
			}()

			env := LoadEnv(sc.files...)
			if env == nil {
				t.Fatalf("expected non-nil Env struct for scenario %s", sc.name)
			}

			// Verify required fields have fallback defaults
			if env.Database.Hostname == "" {
				t.Errorf("expected default DB Hostname, got empty")
			}
			if env.Redis.Hostname == "" {
				t.Errorf("expected default Redis Hostname, got empty")
			}
			if env.RabbitMQ.Hostname == "" {
				t.Errorf("expected default RabbitMQ Hostname, got empty")
			}
			if env.JWT.Secret == "" {
				t.Errorf("expected default JWT Secret, got empty")
			}
			if env.EncryptionKey == "" {
				t.Errorf("expected default EncryptionKey, got empty")
			}
		})
	}
}

// TestAdversarial_DatabaseUrl_NilPointerSafety verifies that calling DatabaseUrl()
// when global Cfg is nil never causes a nil-pointer dereference panic across all variations.
func TestAdversarial_DatabaseUrl_NilPointerSafety(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	// Ensure global Cfg is strictly nil
	Cfg = nil

	dbVariations := []struct {
		name        string
		db          Database
		expectedURL string
	}{
		{
			name: "standard postgres with nil Cfg",
			db: Database{
				Hostname:   "db.internal",
				Port:       "5432",
				Provider:   "postgres",
				DBName:     "app_db",
				DBUser:     "app_user",
				DBPassword: "secret_password",
			},
			expectedURL: "host=db.internal port=5432 user=app_user password=secret_password dbname=app_db sslmode=disable",
		},
		{
			name:        "zero-value Database struct with nil Cfg",
			db:          Database{},
			expectedURL: "", // Provider is "" (not postgres)
		},
		{
			name: "zero-value Database struct with postgres provider and nil Cfg",
			db: Database{
				Provider: "postgres",
			},
			expectedURL: "host= port= user= password= dbname= sslmode=disable",
		},
		{
			name: "sqlite provider with nil Cfg",
			db: Database{
				Provider: "sqlite",
				DBName:   "test.db",
			},
			expectedURL: "",
		},
		{
			name: "mysql provider with nil Cfg",
			db: Database{
				Provider: "mysql",
				DBName:   "test_mysql",
			},
			expectedURL: "",
		},
	}

	for _, tc := range dbVariations {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DatabaseUrl() panicked with nil Cfg: %v", r)
				}
			}()

			url := tc.db.DatabaseUrl()
			if url != tc.expectedURL {
				t.Errorf("got %q, want %q", url, tc.expectedURL)
			}
		})
	}
}

// TestAdversarial_DatabaseUrl_NodeEnvVariations verifies sslmode selection
// under all permutations of NodeEnv values.
func TestAdversarial_DatabaseUrl_NodeEnvVariations(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	db := Database{
		Hostname:   "localhost",
		Port:       "5432",
		Provider:   "postgres",
		DBName:     "postgres",
		DBUser:     "postgres",
		DBPassword: "password",
	}

	nodeEnvCases := []struct {
		nodeEnv         string
		expectedSSLMode string
	}{
		{"production", "sslmode=require"},
		{"development", "sslmode=disable"},
		{"test", "sslmode=disable"},
		{"staging", "sslmode=disable"},
		{"qa", "sslmode=disable"},
		{"local", "sslmode=disable"},
		{"", "sslmode=disable"},
		{"Production", "sslmode=disable"}, // Exact case match required
		{"PRODUCTION", "sslmode=disable"},
	}

	for _, tc := range nodeEnvCases {
		t.Run("NodeEnv="+tc.nodeEnv, func(t *testing.T) {
			Cfg = &Env{NodeEnv: tc.nodeEnv}

			url := db.DatabaseUrl()
			expectedPattern := fmt.Sprintf("host=localhost port=5432 user=postgres password=password dbname=postgres %s", tc.expectedSSLMode)
			if url != expectedPattern {
				t.Errorf("NodeEnv=%q: got %q, want %q", tc.nodeEnv, url, expectedPattern)
			}
		})
	}
}

// TestAdversarial_DatabaseUrl_ConcurrentStress verifies that concurrent calls
// to DatabaseUrl() under goroutines with varying Cfg pointers do not cause data races or panics.
func TestAdversarial_DatabaseUrl_ConcurrentStress(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	const goroutines = 64
	const iterations = 100

	db := Database{
		Hostname:   "db.host",
		Port:       "5432",
		Provider:   "postgres",
		DBName:     "dbname",
		DBUser:     "dbuser",
		DBPassword: "dbpassword",
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(routineID int) {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				url := db.DatabaseUrl()
				if url == "" {
					t.Errorf("goroutine %d got empty database url", routineID)
					return
				}
			}
		}(g)
	}

	wg.Wait()
}

// TestAdversarial_RabbitUrl_Safety verifies RabbitUrl formatting and safety.
func TestAdversarial_RabbitUrl_Safety(t *testing.T) {
	rmq := RabbitMQ{
		Hostname: "rmq.server",
		Port:     "5672",
		Username: "admin",
		Password: "complex_password!@#",
	}

	expected := "amqp://admin:complex_password!@#@rmq.server:5672"
	if url := rmq.RabbitUrl(); url != expected {
		t.Errorf("got %q, want %q", url, expected)
	}

	// Zero-value check
	zeroRMQ := RabbitMQ{}
	if url := zeroRMQ.RabbitUrl(); url != "amqp://:@:" {
		t.Errorf("got %q, want 'amqp://:@:'", url)
	}
}

// TestAdversarial_EnvKey_BoundaryFuzzing tests boundary cases, whitespaces,
// unicode, negative numbers, and extreme values.
func TestAdversarial_EnvKey_BoundaryFuzzing(t *testing.T) {
	// 1. EnvKeyInt boundaries
	os.Setenv("FUZZ_INT_MAX", "2147483647")
	os.Setenv("FUZZ_INT_MIN", "-2147483648")
	os.Setenv("FUZZ_INT_OVERFLOW", "999999999999999999999999999999999999")
	os.Setenv("FUZZ_INT_FLOAT", "123.456")
	os.Setenv("FUZZ_INT_HEX", "0x1f")
	os.Setenv("FUZZ_INT_WHITESPACE", "  789  ")

	defer func() {
		os.Unsetenv("FUZZ_INT_MAX")
		os.Unsetenv("FUZZ_INT_MIN")
		os.Unsetenv("FUZZ_INT_OVERFLOW")
		os.Unsetenv("FUZZ_INT_FLOAT")
		os.Unsetenv("FUZZ_INT_HEX")
		os.Unsetenv("FUZZ_INT_WHITESPACE")
	}()

	if val := EnvKeyInt("FUZZ_INT_MAX", 0); val != 2147483647 {
		t.Errorf("expected 2147483647, got %d", val)
	}
	if val := EnvKeyInt("FUZZ_INT_MIN", 0); val != -2147483648 {
		t.Errorf("expected -2147483648, got %d", val)
	}
	if val := EnvKeyInt("FUZZ_INT_OVERFLOW", 99); val != 99 {
		t.Errorf("expected fallback 99 on overflow, got %d", val)
	}
	if val := EnvKeyInt("FUZZ_INT_FLOAT", 99); val != 99 {
		t.Errorf("expected fallback 99 on float string, got %d", val)
	}
	if val := EnvKeyInt("FUZZ_INT_HEX", 99); val != 99 {
		t.Errorf("expected fallback 99 on hex string, got %d", val)
	}
	if val := EnvKeyInt("FUZZ_INT_WHITESPACE", 0); val != 789 {
		t.Errorf("expected 789 for trimmed whitespace int, got %d", val)
	}

	// 2. EnvKeyBool variations with whitespace
	boolCases := []struct {
		envVal   string
		expected bool
	}{
		{"  true  ", true},
		{"  1  ", true},
		{"  false  ", false},
		{"  0  ", false},
		{"  yes  ", true},
		{"  no  ", false},
	}

	for _, bc := range boolCases {
		os.Setenv("FUZZ_BOOL", bc.envVal)
		got := EnvKeyBool("FUZZ_BOOL", !bc.expected)
		if got != bc.expected {
			t.Errorf("EnvKeyBool(%q) = %v; want %v", bc.envVal, got, bc.expected)
		}
	}
	os.Unsetenv("FUZZ_BOOL")
}
