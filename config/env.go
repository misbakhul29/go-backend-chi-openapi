package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Database struct {
	Hostname   string
	Port       string
	Provider   string
	DBName     string
	DBUser     string
	DBPassword string
}

type Redis struct {
	Hostname string
	Port     string
	Password string
}

type RabbitMQ struct {
	Hostname string
	Port     string
	Username string
	Password string
}

type JWT struct {
	Secret     string
	AccessTTL  int // seconds, default 900 (15 min)
	RefreshTTL int // seconds, default 604800 (7 days)
}

var Cfg *Env

type Env struct {
	APPName       string
	NodeEnv       string
	Port          string
	Database      Database
	Redis         Redis
	RabbitMQ      RabbitMQ
	JWT           JWT
	EncryptionKey string
}

func LoadEnv() *Env {
	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file")
	}

	Cfg = &Env{
		APPName: EnvKey("APP_NAME", "Backend Framework"),
		NodeEnv: EnvKey("NODE_ENV", "development"),
		Port:    EnvKey("PORT", "8080"),
		Database: Database{
			Hostname:   EnvKey("DB_HOST", "localhost"),
			Port:       EnvKey("DB_PORT", "5432"),
			Provider:   EnvKey("DB_PROVIDER", "postgres"),
			DBName:     EnvKey("DB_NAME", "postgres"),
			DBUser:     EnvKey("DB_USER", "postgres"),
			DBPassword: EnvKey("DB_PASSWORD", "admin"),
		},
		Redis: Redis{
			Hostname: EnvKey("REDIS_HOST", "localhost"),
			Port:     EnvKey("REDIS_PORT", "6379"),
			Password: EnvKey("REDIS_PASSWORD", ""),
		},
		RabbitMQ: RabbitMQ{
			Hostname: EnvKey("RABBITMQ_HOST", "localhost"),
			Port:     EnvKey("RABBITMQ_PORT", "5672"),
			Username: EnvKey("RABBITMQ_USER", "guest"),
			Password: EnvKey("RABBITMQ_PASSWORD", "guest"),
		},
		JWT: JWT{
			Secret:     EnvKey("JWT_SECRET", "super-secret-key-change-in-production-1234567890"),
			AccessTTL:  EnvKeyInt("JWT_ACCESS_TTL", 900),
			RefreshTTL: EnvKeyInt("JWT_REFRESH_TTL", 604800),
		},
		EncryptionKey: EnvKey("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

	// Fail-fast validation for mandatory configurations
	validateMandatoryEnv("DB_HOST", Cfg.Database.Hostname)
	validateMandatoryEnv("DB_PORT", Cfg.Database.Port)
	validateMandatoryEnv("DB_NAME", Cfg.Database.DBName)
	validateMandatoryEnv("DB_USER", Cfg.Database.DBUser)
	validateMandatoryEnv("REDIS_HOST", Cfg.Redis.Hostname)
	validateMandatoryEnv("REDIS_PORT", Cfg.Redis.Port)
	validateMandatoryEnv("RABBITMQ_HOST", Cfg.RabbitMQ.Hostname)
	validateMandatoryEnv("RABBITMQ_PORT", Cfg.RabbitMQ.Port)
	validateMandatoryEnv("JWT_SECRET", Cfg.JWT.Secret)
	validateMandatoryEnv("ENCRYPTION_KEY", Cfg.EncryptionKey)

	return Cfg
}

func validateMandatoryEnv(key, val string) {
	if val == "" {
		panic(fmt.Sprintf("FATAL: Environment variable %s is mandatory but not set", key))
	}
}

func EnvKey(key string, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func EnvKeyInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
		return fallback
	}
	return n
}

func (d Database) DatabaseUrl() string {
	sslmode := "disable"
	if Cfg.NodeEnv != "development" {
		sslmode = "require"
	}
	if d.Provider == "postgres" {
		return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", d.Hostname, d.Port, d.DBUser, d.DBPassword, d.DBName, sslmode)
	}
	return ""
}

func (r RabbitMQ) RabbitUrl() string {
	return fmt.Sprintf("amqp://%s:%s@%s:%s", r.Username, r.Password, r.Hostname, r.Port)
}
