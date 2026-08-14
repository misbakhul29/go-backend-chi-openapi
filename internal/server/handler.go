package handler

import (
	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/internal/auth"
	"github.com/misbakhul29/backend-framework/internal/health"
	"github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// Server meng-embed sub-handler per domain
type Server struct {
	*health.HealthHandler
	*auth.AuthHandler
}

func NewServer(db *gorm.DB, redis *redis.Client, rabbitmq *amqp091.Connection, jwtCfg config.JWT) *Server {
	authRepo := auth.NewRepository(db)
	authService := auth.NewService(authRepo, db, jwtCfg)

	return &Server{
		HealthHandler: health.NewHandler(),
		AuthHandler:   auth.NewHandler(authService),
	}
}
