package status

import (
	"github.com/getkin/kin-openapi/openapi3"
)

func RegisterSchemas(schemas openapi3.Schemas) {
	schemas["SuccessGetStatusResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"status": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "ok",
				Description: "Status indicator",
				Enum:        []any{"ok", "maintenance"},
			}),
			"timestamp": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Format:      "date-time",
				Example:     "2023-10-26T10:00:00Z",
				Description: "ISO 8601 timestamp of the response",
			}),
		},
	})

	schemas["NotFoundGetStatusResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "Not Found",
				Description: "Error message",
			}),
		},
	})

	schemas["InternalErrorGetStatusResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "Internal server error",
				Description: "Error message",
			}),
		},
	})

	schemas["SuccessPermissionCheckResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "has debug permission",
			}),
		},
	})

	schemas["UnauthorizedResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "Unauthorized",
				Description: "Error message",
			}),
		},
	})

	schemas["ForbiddenResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "Forbidden",
				Description: "Error message",
			}),
		},
	})
}
