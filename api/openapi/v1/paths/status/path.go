package status

import (
	"github.com/getkin/kin-openapi/openapi3"
)

func RegisterPaths(paths *openapi3.Paths) {
	responses := openapi3.NewResponses()
	responses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("API is healthy and running"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessGetStatusResponse", nil),
				},
			},
		},
	})
	responses.Set("404", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Not Found"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/NotFoundGetStatusResponse", nil),
				},
			},
		},
	})
	responses.Set("500", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Internal server error"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/InternalErrorGetStatusResponse", nil),
				},
			},
		},
	})

	paths.Set("/status", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getStatus",
			Summary:     "Get API Status",
			Tags:        []string{"Status"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			Security:  &openapi3.SecurityRequirements{},
			Responses: responses,
		},
	})
}

func pointerToString(s string) *string {
	return &s
}
