package auth

import (
	"github.com/getkin/kin-openapi/openapi3"
)

func RegisterSchemas(schemas openapi3.Schemas) {
	schemas["SuccessGetMeResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"id": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "123",
				Description: "User ID",
			}),
			"name": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "John Doe",
				Description: "User's full name",
			}),
			"email": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Format:      "email",
				Example:     "john@example.com",
				Description: "User's email address",
			}),
		},
	})

	schemas["UnauthorizedGetMeResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "Unauthorized",
				Description: "Error message",
			}),
		},
	})

	schemas["InternalErrorGetMeResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "Internal server error",
				Description: "Error message",
			}),
		},
	})
}
