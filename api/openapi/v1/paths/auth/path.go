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

	// /auth/register endpoint
	registerResponses := openapi3.NewResponses()
	registerResponses.Set("201", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("User successfully registered"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessRegisterResponse", nil),
				},
			},
		},
	})
	registerResponses.Set("400", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Bad Request"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/BadRequestResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/register", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postAuthRegister",
			Summary:     "Register a new user",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("#/components/schemas/RegisterRequest", nil),
						},
					},
				},
			},
			Responses: registerResponses,
		},
	})

	// /auth/login endpoint
	loginResponses := openapi3.NewResponses()
	loginResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("User successfully logged in"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessLoginResponse", nil),
				},
			},
		},
	})
	loginResponses.Set("401", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/UnauthorizedGetMeResponse", nil),
				},
			},
		},
	})
	loginResponses.Set("400", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Bad Request"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/BadRequestResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/login", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postAuthLogin",
			Summary:     "Authenticate user and retrieve access token",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("#/components/schemas/LoginRequest", nil),
						},
					},
				},
			},
			Responses: loginResponses,
		},
	})

	// /auth/logout endpoint
	logoutResponses := openapi3.NewResponses()
	logoutResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("User successfully logged out"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessLogoutResponse", nil),
				},
			},
		},
	})
	logoutResponses.Set("401", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/UnauthorizedGetMeResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/logout", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postAuthLogout",
			Summary:     "Log out current user and revoke active session",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			Security: &openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"BearerAuth": []string{},
				},
			},
			Responses: logoutResponses,
		},
	})

	// /auth/me endpoint
	paths.Set("/auth/me", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getMe",
			Summary:     "Get current authenticated user",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
				"x-audit":       true,
				"x-permission": map[string]string{
					"module":   "auth",
					"resource": "me",
					"action":   "read",
				},
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
