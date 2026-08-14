package auth

import (
	"github.com/getkin/kin-openapi/openapi3"
)

func RegisterPaths(paths *openapi3.Paths) {
	responses := openapi3.NewResponses()
	responses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Successfully retrieved user info"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessGetMeResponse", nil),
				},
			},
		},
	})
	responses.Set("401", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/UnauthorizedGetMeResponse", nil),
				},
			},
		},
	})
	responses.Set("500", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Internal server error"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/InternalErrorGetMeResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/me", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getMe",
			Summary:     "Get current authenticated user",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			Security: &openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"BearerAuth": []string{},
				},
			},
			Responses: responses,
		},
	})
}

func pointerToString(s string) *string {
	return &s
}
