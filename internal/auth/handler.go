package auth

import (
	"encoding/json"
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"

	apiv1 "github.com/misbakhul29/learning-chi/api/openapi/v1/generated"
	"github.com/misbakhul29/learning-chi/pkg/security"
)

type AuthHandler struct{}

func NewHandler() *AuthHandler {
	return &AuthHandler{}
}

// GetMe mengembalikan data user yang sedang login
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	principal, _ := security.PrincipalFromContext(r.Context())

	resp := apiv1.SuccessGetMeResponse{
		Id:    new(principal.UserID.String()),
		Name:  new("John Doe"),
		Email: new(openapi_types.Email("jhon.dow@mail.com")),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
