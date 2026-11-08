package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Database struct {
	Hostname          string
	Port              string
	Provider          string
	DBName            string
	DBUser            string
	DBPassword        string
	EnableMultiTenant bool
}

type Redis struct {
	Hostname string
	Port     string
	Password string
}

type RabbitMQ struct {
	Hostname       string
	Port           string
	Username       string
	Password       string
	ExchangePrefix string
}

type JWT struct {
	Secret     string
	AccessTTL  int
	RefreshTTL int
}

type OAuthProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type AppleOAuth struct {
	ClientID    string
	TeamID      string
	KeyID       string
	PrivateKey  string
	RedirectURL string
}

type OAuth struct {
	Google   OAuthProvider
	GitHub   OAuthProvider
	Facebook OAuthProvider
	Discord  OAuthProvider
	Twitter  OAuthProvider
	Apple    AppleOAuth
}

type SAML struct {
	EntityID    string
	ACSURL      string
	IdPEntityID string
	IdPSSOURL   string
	IdPCertPEM  string
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
	OAuth         OAuth
	SAML          SAML
	EncryptionKey string
}

func isTestEnv() bool {
	if nodeEnv := os.Getenv("NODE_ENV"); nodeEnv != "" {
		return nodeEnv == "test"
	}
	return Cfg != nil && Cfg.NodeEnv == "test"
}

func LoadEnv(filenames ...string) *Env {
	if err := godotenv.Load(filenames...); err != nil {
		if !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(err) {
			log.Printf("warning: error loading .env file: %v", err)
		}
	}

	Cfg = &Env{
		APPName: EnvKey("APP_NAME", "Backend Framework"),
		NodeEnv: EnvKey("NODE_ENV", "development"),
		Port:    EnvKey("PORT", "8800"),
		Database: Database{
			Hostname:          EnvKey("DB_HOST", "localhost"),
			Port:              EnvKey("DB_PORT", "5432"),
			Provider:          EnvKey("DB_PROVIDER", "postgres"),
			DBName:            EnvKey("DB_NAME", "postgres"),
			DBUser:            EnvKey("DB_USER", "postgres"),
			DBPassword:        EnvKey("DB_PASSWORD", "admin"),
			EnableMultiTenant: EnvKeyBool("TENANT_ENABLED", false),
		},
		Redis: Redis{
			Hostname: EnvKey("REDIS_HOST", "localhost"),
			Port:     EnvKey("REDIS_PORT", "6379"),
			Password: EnvKey("REDIS_PASSWORD", ""),
		},
		RabbitMQ: RabbitMQ{
			Hostname:       EnvKey("RABBITMQ_HOST", "localhost"),
			Port:           EnvKey("RABBITMQ_PORT", "5672"),
			Username:       EnvKey("RABBITMQ_USER", "guest"),
			Password:       EnvKey("RABBITMQ_PASSWORD", "guest"),
			ExchangePrefix: EnvKey("RABBITMQ_EXCHANGE_PREFIX", EnvKey("APP_NAME", "app")),
		},
		JWT: JWT{
			Secret:     EnvKey("JWT_SECRET", "super-secret-key-change-in-production-1234567890"),
			AccessTTL:  EnvKeyInt("JWT_ACCESS_TTL", 900),
			RefreshTTL: EnvKeyInt("JWT_REFRESH_TTL", 604800),
		},
		OAuth: OAuth{
			Google: OAuthProvider{
				ClientID:     EnvKey("GOOGLE_CLIENT_ID", ""),
				ClientSecret: EnvKey("GOOGLE_CLIENT_SECRET", ""),
				RedirectURL:  EnvKey("GOOGLE_REDIRECT_URL", ""),
			},
			GitHub: OAuthProvider{
				ClientID:     EnvKey("GITHUB_CLIENT_ID", ""),
				ClientSecret: EnvKey("GITHUB_CLIENT_SECRET", ""),
				RedirectURL:  EnvKey("GITHUB_REDIRECT_URL", ""),
			},
			Facebook: OAuthProvider{
				ClientID:     EnvKey("FACEBOOK_CLIENT_ID", ""),
				ClientSecret: EnvKey("FACEBOOK_CLIENT_SECRET", ""),
				RedirectURL:  EnvKey("FACEBOOK_REDIRECT_URL", ""),
			},
			Discord: OAuthProvider{
				ClientID:     EnvKey("DISCORD_CLIENT_ID", ""),
				ClientSecret: EnvKey("DISCORD_CLIENT_SECRET", ""),
				RedirectURL:  EnvKey("DISCORD_REDIRECT_URL", ""),
			},
			Twitter: OAuthProvider{
				ClientID:     EnvKey("TWITTER_CLIENT_ID", ""),
				ClientSecret: EnvKey("TWITTER_CLIENT_SECRET", ""),
				RedirectURL:  EnvKey("TWITTER_REDIRECT_URL", ""),
			},
			Apple: AppleOAuth{
				ClientID:    EnvKey("APPLE_CLIENT_ID", ""),
				TeamID:      EnvKey("APPLE_TEAM_ID", ""),
				KeyID:       EnvKey("APPLE_KEY_ID", ""),
				PrivateKey:  EnvKey("APPLE_PRIVATE_KEY", ""),
				RedirectURL: EnvKey("APPLE_REDIRECT_URL", ""),
			},
		},
		SAML: SAML{
			EntityID:    EnvKey("SAML_SP_ENTITY_ID", "http://localhost:8800/api/v1/auth/sso/saml/metadata"),
			ACSURL:      EnvKey("SAML_SP_ACS_URL", "http://localhost:8800/api/v1/auth/sso/saml/acs"),
			IdPEntityID: EnvKey("SAML_IDP_ENTITY_ID", ""),
			IdPSSOURL:   EnvKey("SAML_IDP_SSO_URL", ""),
			IdPCertPEM:  EnvKey("SAML_IDP_CERT_PEM", ""),
		},
		EncryptionKey: EnvKey("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

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

	if Cfg.NodeEnv == "production" {
		if Cfg.JWT.Secret == "super-secret-key-change-in-production-1234567890" {
			panic("FATAL: JWT_SECRET must be set to a secure secret in production")
		}
		if Cfg.EncryptionKey == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
			panic("FATAL: ENCRYPTION_KEY must be set to a secure key in production")
		}
	}

	return Cfg
}

func validateMandatoryEnv(key, val string) {
	if isTestEnv() {
		return
	}
	if strings.TrimSpace(val) == "" {
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
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return n
}

func EnvKeyBool(key string, fallback bool) bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if val == "" {
		return fallback
	}
	switch val {
	case "1", "t", "true", "yes", "y":
		return true
	case "0", "f", "false", "no", "n":
		return false
	default:
		return fallback
	}
}

func (d Database) DatabaseUrl() string {
	sslmode := "disable"
	if Cfg != nil && Cfg.NodeEnv == "production" {
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
