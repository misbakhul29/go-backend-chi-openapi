package main

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	apiv1 "github.com/misbakhul29/learning-chi/api/openapi/v1/generated"
	"github.com/misbakhul29/learning-chi/config"
	handler "github.com/misbakhul29/learning-chi/internal/server"
	"github.com/misbakhul29/learning-chi/pkg/observer"
	"github.com/misbakhul29/learning-chi/pkg/security"
)

func main() {
	env := config.LoadEnv()
	r := chi.NewRouter()
	r.Use(observer.Logger)
	r.Use(observer.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to Chi Framework"))
	})

	// Setup security middleware
	swaggerSpec, err := apiv1.GetSpec()
	if err != nil {
		panic("failed to load swagger spec: " + err.Error())
	}
	policyResolver, err := security.NewPolicyResolver(swaggerSpec)
	if err != nil {
		panic("failed to initialize policy resolver: " + err.Error())
	}

	jwtVerifier := &security.DummyJWTVerifier{}
	jwtService := security.NewJWTService(jwtVerifier)
	securityMiddleware := security.NewMiddleware(jwtService, policyResolver)

	server := handler.NewServer()

	r.Route("/api/v1", func(r chi.Router) {
		// Public endpoints (Docs & Welcome root)
		swaggerSetup(r)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Welcome to Chi Framework"))
		})

		// Secure API endpoints defined in OpenAPI specification
		r.Group(func(r chi.Router) {
			r.Use(securityMiddleware.Security)
			apiv1.HandlerFromMux(server, r)
		})
	})

	println("Server started on port ", env.Port)
	http.ListenAndServe(":"+env.Port, r)
}

func swaggerSetup(r chi.Router) {
	r.Get("/docs", swaggerUI())

	root := http.Dir("api/openapi/v1")

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

func swaggerUI() http.HandlerFunc {
	html := `
		<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="SwaggerUI" />
    <title>SwaggerUI</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  </head>
  <body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js" crossorigin></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-standalone-preset.js" crossorigin></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/api/v1/_bundled.yaml',
        dom_id: '#swagger-ui',
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "StandaloneLayout",
      });
    };
  </script>
  </body>
</html>
	`

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(html))
	}
}
