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
		Type:     &openapi3.Types{"object"},
		Required: []string{"name", "email", "password"},
		Properties: openapi3.Schemas{
			"name": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "John Doe",
			}),
			"email": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Format:  "email",
				Example: "john@example.com",
			}),
			"password": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "secretpassword123",
			}),
		},
	})

	schemas["SuccessRegisterResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"id": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "123",
			}),
			"name": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "John Doe",
			}),
			"email": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Format:  "email",
				Example: "john@example.com",
			}),
		},
	})

	// Login Request & Response
	schemas["LoginRequest"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type:     &openapi3.Types{"object"},
		Required: []string{"email", "password"},
		Properties: openapi3.Schemas{
			"email": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Format:  "email",
				Example: "john@example.com",
			}),
			"password": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "secretpassword123",
			}),
		},
	})

	schemas["SuccessLoginResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"accessToken": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			}),
			"refreshToken": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "94fa10d7e6...",
			}),
			"tokenType": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "Bearer",
			}),
			"expiresIn": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"integer"},
				Example: 900,
			}),
			"user": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type: &openapi3.Types{"object"},
				Properties: openapi3.Schemas{
					"id": openapi3.NewSchemaRef("", &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Example: "123",
					}),
					"name": openapi3.NewSchemaRef("", &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Example: "John Doe",
					}),
					"email": openapi3.NewSchemaRef("", &openapi3.Schema{
						Type:    &openapi3.Types{"string"},
						Format:  "email",
						Example: "john@example.com",
					}),
				},
			}),
		},
	})

	// General Error Responses
	schemas["BadRequestResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "invalid request payload",
			}),
		},
	})

	schemas["NotFoundResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"error": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:        &openapi3.Types{"string"},
				Example:     "Not found",
				Description: "Error message",
			}),
		},
	})

	schemas["SuccessLogoutResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "successfully logged out",
			}),
		},
	})

	schemas["ChangeRoleRequest"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type:     &openapi3.Types{"object"},
		Required: []string{"userId", "role"},
		Properties: openapi3.Schemas{
			"userId": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "123",
			}),
			"role": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "MEMBER",
			}),
		},
	})

	schemas["SuccessChangeRoleResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "role successfully updated",
			}),
		},
	})

	// Forgot Password
	schemas["ForgotPasswordRequest"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type:     &openapi3.Types{"object"},
		Required: []string{"email"},
		Properties: openapi3.Schemas{
			"email": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Format:  "email",
				Example: "user@example.com",
			}),
		},
	})

	schemas["SuccessForgotPasswordResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "If your email is registered, you will receive password reset instructions shortly.",
			}),
		},
	})

	// Reset Password
	schemas["ResetPasswordRequest"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type:     &openapi3.Types{"object"},
		Required: []string{"token", "newPassword"},
		Properties: openapi3.Schemas{
			"token": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "94fa10d7e6a5...",
			}),
			"newPassword": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "NewStr0ng#Pass2026",
			}),
		},
	})

	schemas["SuccessResetPasswordResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "Password has been successfully reset.",
			}),
		},
	})

	// Change Password
	schemas["ChangePasswordRequest"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type:     &openapi3.Types{"object"},
		Required: []string{"oldPassword", "newPassword"},
		Properties: openapi3.Schemas{
			"oldPassword": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "OldStr0ng#Pass2025",
			}),
			"newPassword": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "NewStr0ng#Pass2026",
			}),
			"revokeOtherSessions": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"boolean"},
				Default: false,
				Example: true,
			}),
		},
	})

	schemas["SuccessChangePasswordResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "Password successfully updated.",
			}),
		},
	})

	// Refresh Token
	schemas["RefreshRequest"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type:     &openapi3.Types{"object"},
		Required: []string{"refreshToken"},
		Properties: openapi3.Schemas{
			"refreshToken": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "94fa10d7e6...",
			}),
		},
	})

	schemas["SuccessRefreshResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"accessToken": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			}),
			"refreshToken": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "83bc92e5a1...",
			}),
			"tokenType": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "Bearer",
			}),
			"expiresIn": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"integer"},
				Example: 900,
			}),
		},
	})

	// Session Management
	schemas["SessionItem"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type:     &openapi3.Types{"object"},
		Required: []string{"id", "isCurrent", "createdAt", "expiresAt"},
		Properties: openapi3.Schemas{
			"id": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "session-uuid-123",
			}),
			"ipAddress": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "192.168.1.1",
			}),
			"userAgent": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "Mozilla/5.0 ...",
			}),
			"device": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "Chrome on macOS",
			}),
			"isCurrent": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"boolean"},
				Example: true,
			}),
			"lastActiveAt": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:   &openapi3.Types{"string"},
				Format: "date-time",
			}),
			"createdAt": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:   &openapi3.Types{"string"},
				Format: "date-time",
			}),
			"expiresAt": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:   &openapi3.Types{"string"},
				Format: "date-time",
			}),
		},
	})

	schemas["SuccessListSessionsResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"sessions": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:  &openapi3.Types{"array"},
				Items: openapi3.NewSchemaRef("#/components/schemas/SessionItem", nil),
			}),
		},
	})

	schemas["SuccessRevokeSessionResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "session successfully revoked",
			}),
		},
	})

	schemas["SuccessRevokeAllSessionsResponse"] = openapi3.NewSchemaRef("", &openapi3.Schema{
		Type: &openapi3.Types{"object"},
		Properties: openapi3.Schemas{
			"message": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"string"},
				Example: "sessions successfully revoked",
			}),
			"revokedCount": openapi3.NewSchemaRef("", &openapi3.Schema{
				Type:    &openapi3.Types{"integer"},
				Example: 3,
			}),
		},
	})
}
