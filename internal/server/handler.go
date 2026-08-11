package handler

import (
	"github.com/misbakhul29/learning-chi/internal/auth"
	"github.com/misbakhul29/learning-chi/internal/check"
	"github.com/misbakhul29/learning-chi/internal/health"
)

// Server meng-embed sub-handler per domain
type Server struct {
	*health.HealthHandler
	*auth.AuthHandler
	*check.CheckHandler
}

func NewServer() *Server {
	return &Server{
		HealthHandler: health.NewHandler(),
		AuthHandler:   auth.NewHandler(),
		CheckHandler:  check.NewHandler(),
	}
}
