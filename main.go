package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	apiv1 "github.com/misbakhul29/backend-framework/api/openapi/v1/generated"
	"github.com/misbakhul29/backend-framework/config"
	handler "github.com/misbakhul29/backend-framework/internal/server"
	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	"github.com/misbakhul29/backend-framework/pkg/rabbitx"
	"github.com/misbakhul29/backend-framework/pkg/redisx"
	"github.com/misbakhul29/backend-framework/pkg/security"
	"github.com/misbakhul29/backend-framework/pkg/swagger"
)

func main() {
	env := config.LoadEnv()

	// Databas
	DB, err := db.InitDB(env.Database, security.RegisteredPermissions)
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}
	defer db.CloseDB(DB)

	// Redis
	redisClient, err := redisx.InitRedis(env.Redis)
	if err != nil {
		panic("failed to connect to Redis: " + err.Error())
	}
	defer redisClient.Close()

	r := httpx.NewRouter()

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to Chi Framework"))
	})

	// Rabbit
	rmq, err := rabbitx.InitRabbit(env.RabbitMQ)
	if err != nil {
		panic("failed to connect to RabbitMQ: " + err.Error())
	}
	defer rmq.Close()

	// Setup security middleware
	swaggerSpec, err := apiv1.GetSpec()
	if err != nil {
		panic("failed to load swagger spec: " + err.Error())
	}
	policyResolver, err := security.NewPolicyResolver(swaggerSpec)
	if err != nil {
		panic("failed to initialize policy resolver: " + err.Error())
	}

	jwtVerifier := security.NewJWTVerifier([]byte(env.JWT.Secret))
	jwtService := security.NewJWTService(jwtVerifier)
	securityMiddleware := security.NewMiddleware(jwtService, policyResolver, redisClient, DB)

	server := handler.NewServer(DB, redisClient, rmq, env.JWT)

	r.Route("/api/v1", func(r chi.Router) {
		// Public endpoints (Docs & Welcome root)
		swagger.Setup(r)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Welcome to Chi Framework"))
		})

		// Secure API endpoints defined in OpenAPI specification
		r.Group(func(r chi.Router) {
			r.Use(securityMiddleware.RateLimit)
			r.Use(securityMiddleware.Security)
			r.Use(securityMiddleware.Audit)
			apiv1.HandlerFromMux(server, r)
		})
	})

	srv := &http.Server{
		Addr:    ":" + env.Port,
		Handler: r,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		observer.Log.Info("Server started", "port", env.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic("failed to start server: " + err.Error())
		}
	}()

	<-stop
	observer.Log.Info("Shutting down server gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		observer.Log.Error("Server forced to shutdown", "error", err)
	} else {
		observer.Log.Info("Server gracefully stopped")
	}
}
