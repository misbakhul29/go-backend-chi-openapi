package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
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
	authService := auth.NewService(authRepo, db, redis, jwtCfg)

	return &Server{
		HealthHandler: health.NewHandler(),
		AuthHandler:   auth.NewHandler(authService),
	}
}

// MountRoutes mounts domain route trees directly onto a Chi router.
func (s *Server) MountRoutes(r chi.Router, authMiddleware func(http.Handler) http.Handler) {
	s.AuthHandler.RegisterRoutes(r, authMiddleware)
}
