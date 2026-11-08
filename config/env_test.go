package config

import (
	"os"
	"testing"
)

func TestLoadEnv_NoDotEnvFile(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	env := LoadEnv("non_existent_env_file.env")
	if env == nil {
		t.Fatal("expected non-nil Env struct")
	}

	if env.NodeEnv != "test" {
		t.Errorf("expected NodeEnv 'test', got %q", env.NodeEnv)
	}
	if env.Port == "" {
		t.Errorf("expected default Port, got empty string")
	}
	if env.Database.Hostname == "" {
		t.Errorf("expected default DB Hostname, got empty string")
	}
	if env.RabbitMQ.ExchangePrefix != "app" && env.RabbitMQ.ExchangePrefix != env.APPName {
		t.Errorf("expected default RabbitMQ.ExchangePrefix, got %q", env.RabbitMQ.ExchangePrefix)
	}
}

func TestLoadEnv_WithEnvironmentVariables(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "test")
	os.Setenv("APP_NAME", "Custom App")
	os.Setenv("PORT", "9999")
	os.Setenv("RABBITMQ_EXCHANGE_PREFIX", "custom_queue")
	os.Setenv("TENANT_ENABLED", "true")

	defer func() {
		os.Unsetenv("NODE_ENV")
		os.Unsetenv("APP_NAME")
		os.Unsetenv("PORT")
		os.Unsetenv("RABBITMQ_EXCHANGE_PREFIX")
		os.Unsetenv("TENANT_ENABLED")
	}()

	env := LoadEnv()
	if env.APPName != "Custom App" {
		t.Errorf("expected APPName 'Custom App', got %q", env.APPName)
	}
	if env.Port != "9999" {
		t.Errorf("expected Port '9999', got %q", env.Port)
	}
	if env.RabbitMQ.ExchangePrefix != "custom_queue" {
		t.Errorf("expected ExchangePrefix 'custom_queue', got %q", env.RabbitMQ.ExchangePrefix)
	}
	if !env.Database.EnableMultiTenant {
		t.Errorf("expected EnableMultiTenant true, got false")
	}
}

func TestEnvKey_Helpers(t *testing.T) {
	// EnvKey fallback
	if val := EnvKey("NON_EXISTENT_VAR_12345", "fallback_val"); val != "fallback_val" {
		t.Errorf("expected 'fallback_val', got %q", val)
	}
	os.Setenv("TEST_KEY_EXISTS", "hello")
	defer os.Unsetenv("TEST_KEY_EXISTS")
	if val := EnvKey("TEST_KEY_EXISTS", "fallback"); val != "hello" {
		t.Errorf("expected 'hello', got %q", val)
	}

	// EnvKeyInt
	if val := EnvKeyInt("NON_EXISTENT_INT", 42); val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
	os.Setenv("TEST_INT_VALID", "100")
	defer os.Unsetenv("TEST_INT_VALID")
	if val := EnvKeyInt("TEST_INT_VALID", 42); val != 100 {
		t.Errorf("expected 100, got %d", val)
	}
	os.Setenv("TEST_INT_INVALID", "not-a-number")
	defer os.Unsetenv("TEST_INT_INVALID")
	if val := EnvKeyInt("TEST_INT_INVALID", 42); val != 42 {
		t.Errorf("expected fallback 42 for invalid integer, got %d", val)
	}

	// EnvKeyBool
	testCasesBool := []struct {
		envVal   string
		fallback bool
		expected bool
	}{
		{"1", false, true},
		{"true", false, true},
		{"TRUE", false, true},
		{"yes", false, true},
		{"y", false, true},
		{"0", true, false},
		{"false", true, false},
		{"FALSE", true, false},
		{"no", true, false},
		{"n", true, false},
		{"invalid", true, true},
		{"invalid", false, false},
	}

	for _, tc := range testCasesBool {
		os.Setenv("TEST_BOOL_VAR", tc.envVal)
		got := EnvKeyBool("TEST_BOOL_VAR", tc.fallback)
		if got != tc.expected {
			t.Errorf("EnvKeyBool(%q, %v) = %v; want %v", tc.envVal, tc.fallback, got, tc.expected)
		}
	}
	os.Unsetenv("TEST_BOOL_VAR")
}

func TestDatabaseUrl_NilConfigSafe(t *testing.T) {
	// Preserve and restore Cfg
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	Cfg = nil
	db := Database{
		Hostname: "localhost",
		Port:     "5432",
		Provider: "postgres",
		DBName:   "testdb",
		DBUser:   "user",
		DBPassword: "password",
	}

	url := db.DatabaseUrl()
	expected := "host=localhost port=5432 user=user password=password dbname=testdb sslmode=disable"
	if url != expected {
		t.Errorf("expected %q, got %q", expected, url)
	}

	// Production config should select sslmode=require
	Cfg = &Env{NodeEnv: "production"}
	urlProd := db.DatabaseUrl()
	expectedProd := "host=localhost port=5432 user=user password=password dbname=testdb sslmode=require"
	if urlProd != expectedProd {
		t.Errorf("expected %q, got %q", expectedProd, urlProd)
	}

	// Other provider should return empty string
	dbOther := Database{Provider: "mysql"}
	if dbOther.DatabaseUrl() != "" {
		t.Errorf("expected empty string for non-postgres provider, got %q", dbOther.DatabaseUrl())
	}
}

func TestValidateMandatoryEnv_TestEnvTolerant(t *testing.T) {
	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("did not expect panic in test environment, but got: %v", r)
		}
	}()

	validateMandatoryEnv("TEST_VAR", "")
}

func TestValidateMandatoryEnv_NonTestPanics(t *testing.T) {
	os.Setenv("NODE_ENV", "development")
	defer os.Unsetenv("NODE_ENV")

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for empty mandatory var in development, but did not panic")
		}
	}()

	validateMandatoryEnv("MANDATORY_VAR", "")
}

func TestLoadEnv_ProductionPlaceholderPanics(t *testing.T) {
	originalCfg := Cfg
	defer func() { Cfg = originalCfg }()

	os.Setenv("NODE_ENV", "production")
	os.Setenv("DB_HOST", "db.internal")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_NAME", "prod_db")
	os.Setenv("DB_USER", "prod_user")
	os.Setenv("REDIS_HOST", "redis.internal")
	os.Setenv("REDIS_PORT", "6379")
	os.Setenv("RABBITMQ_HOST", "rmq.internal")
	os.Setenv("RABBITMQ_PORT", "5672")
	os.Setenv("JWT_SECRET", "super-secret-key-change-in-production-1234567890") // default placeholder

	defer func() {
		os.Unsetenv("NODE_ENV")
		os.Unsetenv("DB_HOST")
		os.Unsetenv("DB_PORT")
		os.Unsetenv("DB_NAME")
		os.Unsetenv("DB_USER")
		os.Unsetenv("REDIS_HOST")
		os.Unsetenv("REDIS_PORT")
		os.Unsetenv("RABBITMQ_HOST")
		os.Unsetenv("RABBITMQ_PORT")
		os.Unsetenv("JWT_SECRET")
	}()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic in production with default JWT_SECRET placeholder, but did not panic")
		}
	}()

	LoadEnv("non_existent.env")
}
