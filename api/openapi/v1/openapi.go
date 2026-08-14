package openapi

import (
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/misbakhul29/backend-framework/api/openapi/v1/paths/auth"
	"github.com/misbakhul29/backend-framework/api/openapi/v1/paths/status"
)

func BuildSpec() *openapi3.T {
	swagger := &openapi3.T{
		OpenAPI: "3.1.0",
		Info: &openapi3.Info{
			Title:       "Backend Framework API",
			Description: "OpenAPI Swagger Docs",
			Version:     "1.0.1",
			License: &openapi3.License{
				Name: "MIT",
				URL:  "https://opensource.org/licenses/MIT",
			},
		},
		Servers: openapi3.Servers{
			&openapi3.Server{
				URL:         "/api/v1",
				Description: "API v1",
			},
		},
		Paths: &openapi3.Paths{},
		Components: &openapi3.Components{
			SecuritySchemes: openapi3.SecuritySchemes{
				"BearerAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:   "http",
						Scheme: "bearer",
					},
				},
			},
			Schemas: make(openapi3.Schemas),
		},
	}

	// Register schemas
	status.RegisterSchemas(swagger.Components.Schemas)
	auth.RegisterSchemas(swagger.Components.Schemas)

	// Register paths
	status.RegisterPaths(swagger.Paths)
	auth.RegisterPaths(swagger.Paths)

	return swagger
}
