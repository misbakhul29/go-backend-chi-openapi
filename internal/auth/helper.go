package auth

import (
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// toEmailPointer converts a raw string to an openapi_types.Email pointer.
func toEmailPointer(s string) *openapi_types.Email {
	email := openapi_types.Email(s)
	return &email
}

// toStrPointer converts a raw string to a string pointer.
func toStrPointer(s string) *string {
	return &s
}
