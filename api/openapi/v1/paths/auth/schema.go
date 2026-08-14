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

	// Register Request & Response
	schemas["RegisterRequest"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Required: []string{"name", "email", "password"},
		Properties: openapi3.Schemas{
			"name": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "John Doe",
			}),
			"email": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Format: "email",
				Example: "john@example.com",
			}),
			"password": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "secretpassword123",
			}),
		},
	})

	schemas["SuccessRegisterResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"id": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "123",
			}),
			"name": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "John Doe",
			}),
			"email": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Format: "email",
				Example: "john@example.com",
			}),
		},
	})

	// Login Request & Response
	schemas["LoginRequest"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Required: []string{"email", "password"},
		Properties: openapi3.Schemas{
			"email": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Format: "email",
				Example: "john@example.com",
			}),
			"password": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "secretpassword123",
			}),
		},
	})

	schemas["SuccessLoginResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"accessToken": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			}),
			"user": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"object"},
				Properties: openapi3.Schemas{
					"id": openapi3.NewSchemaRef("", &openapi3.Schema{
						Type: &openapi3.Types{"string"},
						Example: "123",
					}),
					"name": openapi3.NewSchemaRef("", &openapi3.Schema{
						Type: &openapi3.Types{"string"},
						Example: "John Doe",
					}),
					"email": openapi3.NewSchemaRef("", &openapi3.Schema{
						Type: &openapi3.Types{"string"},
						Format: "email",
						Example: "john@example.com",
					}),
				},
			}),
		},
	})

	// General Bad Request Error Response
	schemas["BadRequestResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "invalid request payload",
			}),
		},
	})

	schemas["SuccessLogoutResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"string"},
				Example: "successfully logged out",
			}),
		},
	})
}
