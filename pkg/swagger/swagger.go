package swagger

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/misbakhul29/backend-framework/config"
)

//go:embed swagger-ui.css
var SwaggerCSS []byte

//go:embed swagger-ui-custom.css
var SwaggerCSSCustom []byte

//go:embed swagger-ui-bundle.js
var SwaggerBundleJS []byte

//go:embed swagger-ui-standalone-preset.js
var SwaggerStandaloneJS []byte

// Setup registers Swagger routes.
// To be called within the "/api/v1" sub-router.
func Setup(r chi.Router) {
	// Serve static Swagger UI files
	r.Get("/swagger/swagger-ui.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(SwaggerCSS)
	})
	r.Get("/swagger/swagger-ui-custom.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(SwaggerCSSCustom)
	})
	r.Get("/swagger/swagger-ui-bundle.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(SwaggerBundleJS)
	})
	r.Get("/swagger/swagger-ui-standalone-preset.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(SwaggerStandaloneJS)
	})

	// Serve Swagger UI HTML
	r.Get("/docs", UI())

	// Serve OpenAPI specs from api/openapi/v1
	specDir := http.Dir("api/openapi/v1/generated")
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(specDir))
		fs.ServeHTTP(w, r)
	})
}

// UI returns the Swagger UI HTML.
func UI() http.HandlerFunc {
	html := `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="{{.Title}}" />
    <title>{{.Title}}</title>
    <!-- Use relative paths so it resolves properly under any router group -->
    <link rel="stylesheet" href="swagger/swagger-ui.css" />
    <link rel="stylesheet" href="swagger/swagger-ui-custom.css" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
      .swagger-ui {
        font-family: 'Inter', sans-serif !important;
      }
      .swagger-ui .topbar {
        background-color: #0f172a !important;
        border-bottom: 1px solid #1e293b;
        padding: 12px 0;
      }
      .swagger-ui .btn.authorize {
        border-color: #10b981 !important;
        color: #10b981 !important;
        background-color: transparent;
      }
      .swagger-ui .btn.authorize svg {
        fill: #10b981 !important;
      }
      .swagger-ui .btn.authorize:hover {
        background-color: #10b981 !important;
        color: #ffffff !important;
      }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="swagger/swagger-ui-bundle.js"></script>
    <script src="swagger/swagger-ui-standalone-preset.js"></script>
    <script>
      window.onload = () => {
        window.ui = SwaggerUIBundle({
          url: '_bundled.yaml', // relative to the current path (/api/v1/docs -> /api/v1/_bundled.yaml)
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
</html>`

	return func(w http.ResponseWriter, r *http.Request) {
		appName := "Backend Framework"
		if config.Cfg != nil && config.Cfg.APPName != "" {
			appName = config.Cfg.APPName
		}
		title := appName + " API Documentation"

		renderedHTML := strings.ReplaceAll(html, "{{.Title}}", title)

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(renderedHTML))
	}
}
