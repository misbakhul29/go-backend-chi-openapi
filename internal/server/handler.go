package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/internal/audit"
	"github.com/misbakhul29/backend-framework/internal/auth"
	"github.com/misbakhul29/backend-framework/internal/auth/oauth"
	"github.com/misbakhul29/backend-framework/internal/auth/sso"
	"github.com/misbakhul29/backend-framework/internal/health"
)

type Server struct {
	*health.HealthHandler
	*auth.AuthHandler
}

func NewServer(db *gorm.DB, redis *redis.Client, rabbitmq *amqp091.Connection, jwtCfg config.JWT) *Server {
	authRepo := auth.NewRepository(db)
	authService := auth.NewService(authRepo, db, redis, jwtCfg)

	auditService := audit.NewService(db, rabbitmq)
	authService.SetAuditService(auditService)

	authHandler := auth.NewHandler(authService)

	reg := oauth.NewRegistry()
	reg.Register(oauth.NewGoogleProvider(oauth.GoogleConfig{
		ClientID:     config.EnvKey("GOOGLE_CLIENT_ID", ""),
		ClientSecret: config.EnvKey("GOOGLE_CLIENT_SECRET", ""),
		RedirectURL:  config.EnvKey("GOOGLE_REDIRECT_URL", ""),
	}, nil))
	reg.Register(oauth.NewGitHubProvider(oauth.GitHubConfig{
		ClientID:     config.EnvKey("GITHUB_CLIENT_ID", ""),
		ClientSecret: config.EnvKey("GITHUB_CLIENT_SECRET", ""),
		RedirectURL:  config.EnvKey("GITHUB_REDIRECT_URL", ""),
	}, nil))
	reg.Register(oauth.NewFacebookProvider(oauth.FacebookConfig{
		ClientID:     config.EnvKey("FACEBOOK_CLIENT_ID", ""),
		ClientSecret: config.EnvKey("FACEBOOK_CLIENT_SECRET", ""),
		RedirectURL:  config.EnvKey("FACEBOOK_REDIRECT_URL", ""),
	}, nil))
	reg.Register(oauth.NewDiscordProvider(oauth.DiscordConfig{
		ClientID:     config.EnvKey("DISCORD_CLIENT_ID", ""),
		ClientSecret: config.EnvKey("DISCORD_CLIENT_SECRET", ""),
		RedirectURL:  config.EnvKey("DISCORD_REDIRECT_URL", ""),
	}, nil))
	reg.Register(oauth.NewTwitterProvider(oauth.TwitterConfig{
		ClientID:     config.EnvKey("TWITTER_CLIENT_ID", ""),
		ClientSecret: config.EnvKey("TWITTER_CLIENT_SECRET", ""),
		RedirectURL:  config.EnvKey("TWITTER_REDIRECT_URL", ""),
	}, nil))
	if apple, err := oauth.NewAppleProvider(oauth.AppleConfig{
		ClientID:    config.EnvKey("APPLE_CLIENT_ID", ""),
		TeamID:      config.EnvKey("APPLE_TEAM_ID", ""),
		KeyID:       config.EnvKey("APPLE_KEY_ID", ""),
		PrivateKey:  config.EnvKey("APPLE_PRIVATE_KEY", ""),
		RedirectURL: config.EnvKey("APPLE_REDIRECT_URL", ""),
	}, nil); err == nil {
		reg.Register(apple)
	}
	authHandler.SetOAuthRegistry(reg)

	samlSvc, _ := sso.NewSAMLService(sso.SAMLSPConfig{
		EntityID:    config.EnvKey("SAML_SP_ENTITY_ID", "http://localhost:8800/api/v1/auth/sso/saml/metadata"),
		ACSURL:      config.EnvKey("SAML_SP_ACS_URL", "http://localhost:8800/api/v1/auth/sso/saml/acs"),
		IdPEntityID: config.EnvKey("SAML_IDP_ENTITY_ID", ""),
		IdPSSOURL:   config.EnvKey("SAML_IDP_SSO_URL", ""),
		IdPCertPEM:  config.EnvKey("SAML_IDP_CERT_PEM", ""),
	})
	authHandler.SetSAMLService(samlSvc)

	return &Server{
		HealthHandler: health.NewHandler(),
		AuthHandler:   authHandler,
	}
}

func (s *Server) MountRoutes(r chi.Router, authMiddleware func(http.Handler) http.Handler) {
	s.AuthHandler.RegisterRoutes(r, authMiddleware)
}
