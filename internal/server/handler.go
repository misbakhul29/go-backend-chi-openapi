package handler

import (
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

func NewServer(db *gorm.DB, redis *redis.Client, rabbitmq *amqp091.Connection, env *config.Env) *Server {
	var jwtCfg config.JWT
	var oauthCfg config.OAuth
	var samlCfg config.SAML
	if env != nil {
		jwtCfg = env.JWT
		oauthCfg = env.OAuth
		samlCfg = env.SAML
	}

	authRepo := auth.NewRepository(db)
	authService := auth.NewService(authRepo, db, redis, jwtCfg)

	auditService := audit.NewService(db, rabbitmq)
	authService.SetAuditService(auditService)

	authHandler := auth.NewHandler(authService)

	reg := oauth.NewRegistry()
	reg.Register(oauth.NewGoogleProvider(oauth.GoogleConfig{
		ClientID:     oauthCfg.Google.ClientID,
		ClientSecret: oauthCfg.Google.ClientSecret,
		RedirectURL:  oauthCfg.Google.RedirectURL,
	}, nil))
	reg.Register(oauth.NewGitHubProvider(oauth.GitHubConfig{
		ClientID:     oauthCfg.GitHub.ClientID,
		ClientSecret: oauthCfg.GitHub.ClientSecret,
		RedirectURL:  oauthCfg.GitHub.RedirectURL,
	}, nil))
	reg.Register(oauth.NewFacebookProvider(oauth.FacebookConfig{
		ClientID:     oauthCfg.Facebook.ClientID,
		ClientSecret: oauthCfg.Facebook.ClientSecret,
		RedirectURL:  oauthCfg.Facebook.RedirectURL,
	}, nil))
	reg.Register(oauth.NewDiscordProvider(oauth.DiscordConfig{
		ClientID:     oauthCfg.Discord.ClientID,
		ClientSecret: oauthCfg.Discord.ClientSecret,
		RedirectURL:  oauthCfg.Discord.RedirectURL,
	}, nil))
	reg.Register(oauth.NewTwitterProvider(oauth.TwitterConfig{
		ClientID:     oauthCfg.Twitter.ClientID,
		ClientSecret: oauthCfg.Twitter.ClientSecret,
		RedirectURL:  oauthCfg.Twitter.RedirectURL,
	}, nil))
	if apple, err := oauth.NewAppleProvider(oauth.AppleConfig{
		ClientID:    oauthCfg.Apple.ClientID,
		TeamID:      oauthCfg.Apple.TeamID,
		KeyID:       oauthCfg.Apple.KeyID,
		PrivateKey:  oauthCfg.Apple.PrivateKey,
		RedirectURL: oauthCfg.Apple.RedirectURL,
	}, nil); err == nil {
		reg.Register(apple)
	}
	authHandler.SetOAuthRegistry(reg)

	samlSvc, _ := sso.NewSAMLService(sso.SAMLSPConfig{
		EntityID:    samlCfg.EntityID,
		ACSURL:      samlCfg.ACSURL,
		IdPEntityID: samlCfg.IdPEntityID,
		IdPSSOURL:   samlCfg.IdPSSOURL,
		IdPCertPEM:  samlCfg.IdPCertPEM,
	})
	authHandler.SetSAMLService(samlSvc)

	return &Server{
		HealthHandler: health.NewHandler(),
		AuthHandler:   authHandler,
	}
}
