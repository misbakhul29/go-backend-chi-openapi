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
			},
			Security: &openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"BearerAuth": []string{},
				},
			},
			Responses: responses,
		},
	})

	// /auth/change-role endpoint
	changeRoleResponses := openapi3.NewResponses()
	changeRoleResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Role successfully updated"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessChangeRoleResponse", nil),
				},
			},
		},
	})
	changeRoleResponses.Set("400", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Bad Request"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/BadRequestResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/change-role", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postAuthChangeRole",
			Summary:     "Update a user's role",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
				"x-permission": map[string]string{
					"module":   "auth",
					"resource": "role",
					"action":   "update",
				},
			},
			Security: &openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"BearerAuth": []string{},
				},
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("#/components/schemas/ChangeRoleRequest", nil),
						},
					},
				},
			},
			Responses: changeRoleResponses,
		},
	})

	// /auth/forgot-password endpoint
	forgotResponses := openapi3.NewResponses()
	forgotResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Password reset instructions dispatched"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessForgotPasswordResponse", nil),
				},
			},
		},
	})
	forgotResponses.Set("400", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Bad Request"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/BadRequestResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/forgot-password", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postAuthForgotPassword",
			Summary:     "Request password reset instructions",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("#/components/schemas/ForgotPasswordRequest", nil),
						},
					},
				},
			},
			Responses: forgotResponses,
		},
	})

	// /auth/reset-password endpoint
	resetResponses := openapi3.NewResponses()
	resetResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Password reset successfully"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessResetPasswordResponse", nil),
				},
			},
		},
	})
	resetResponses.Set("400", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Bad Request"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/BadRequestResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/reset-password", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postAuthResetPassword",
			Summary:     "Reset password using confirmation token",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("#/components/schemas/ResetPasswordRequest", nil),
						},
					},
				},
			},
			Responses: resetResponses,
		},
	})

	// /auth/change-password endpoint
	changePassResponses := openapi3.NewResponses()
	changePassResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Password updated successfully"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessChangePasswordResponse", nil),
				},
			},
		},
	})
	changePassResponses.Set("400", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Bad Request"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/BadRequestResponse", nil),
				},
			},
		},
	})
	changePassResponses.Set("401", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/UnauthorizedResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/change-password", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postAuthChangePassword",
			Summary:     "Change password for authenticated user",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			Security: &openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"BearerAuth": []string{},
				},
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("#/components/schemas/ChangePasswordRequest", nil),
						},
					},
				},
			},
			Responses: changePassResponses,
		},
	})

	// /auth/refresh endpoint
	refreshResponses := openapi3.NewResponses()
	refreshResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Tokens refreshed successfully"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessRefreshResponse", nil),
				},
			},
		},
	})
	refreshResponses.Set("400", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Bad Request"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/BadRequestResponse", nil),
				},
			},
		},
	})
	refreshResponses.Set("401", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/UnauthorizedResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/refresh", &openapi3.PathItem{
		Post: &openapi3.Operation{
			OperationID: "postAuthRefresh",
			Summary:     "Rotate refresh token and issue new token pair",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Required: true,
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: openapi3.NewSchemaRef("#/components/schemas/RefreshRequest", nil),
						},
					},
				},
			},
			Responses: refreshResponses,
		},
	})

	// /auth/sessions endpoint (GET and DELETE)
	sessionsResponses := openapi3.NewResponses()
	sessionsResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Active sessions retrieved successfully"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessListSessionsResponse", nil),
				},
			},
		},
	})
	sessionsResponses.Set("401", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/UnauthorizedResponse", nil),
				},
			},
		},
	})

	revokeAllResponses := openapi3.NewResponses()
	revokeAllResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Sessions revoked successfully"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessRevokeAllSessionsResponse", nil),
				},
			},
		},
	})
	revokeAllResponses.Set("401", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/UnauthorizedResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/sessions", &openapi3.PathItem{
		Get: &openapi3.Operation{
			OperationID: "getAuthSessions",
			Summary:     "List all active sessions for current user",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			Security: &openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"BearerAuth": []string{},
				},
			},
			Responses: sessionsResponses,
		},
		Delete: &openapi3.Operation{
			OperationID: "deleteAuthSessions",
			Summary:     "Revoke all active sessions for current user",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			Security: &openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"BearerAuth": []string{},
				},
			},
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:        "exclude_current",
						In:          openapi3.ParameterInQuery,
						Required:    false,
						Description: "If true, keep current session active",
						Schema: openapi3.NewSchemaRef("", &openapi3.Schema{
							Type: &openapi3.Types{"boolean"},
						}),
					},
				},
			},
			Responses: revokeAllResponses,
		},
	})

	// /auth/sessions/{id} endpoint (DELETE)
	revokeSingleResponses := openapi3.NewResponses()
	revokeSingleResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Session revoked successfully"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/SuccessRevokeSessionResponse", nil),
				},
			},
		},
	})
	revokeSingleResponses.Set("401", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/UnauthorizedResponse", nil),
				},
			},
		},
	})
	revokeSingleResponses.Set("404", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: pointerToString("Not Found"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: openapi3.NewSchemaRef("#/components/schemas/NotFoundResponse", nil),
				},
			},
		},
	})

	paths.Set("/auth/sessions/{id}", &openapi3.PathItem{
		Delete: &openapi3.Operation{
			OperationID: "deleteAuthSessionByID",
			Summary:     "Revoke a specific active session by ID",
			Tags:        []string{"Auth"},
			Extensions: map[string]any{
				"x-api-version": "v1",
			},
			Security: &openapi3.SecurityRequirements{
				openapi3.SecurityRequirement{
					"BearerAuth": []string{},
				},
			},
			Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{
					Value: &openapi3.Parameter{
						Name:        "id",
						In:          openapi3.ParameterInPath,
						Required:    true,
						Description: "Session ID to revoke",
						Schema: openapi3.NewSchemaRef("", &openapi3.Schema{
							Type: &openapi3.Types{"string"},
						}),
					},
				},
			},
			Responses: revokeSingleResponses,
		},
	})
}

func pointerToString(s string) *string {
	return &s
}
