package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"

	apiv1 "github.com/misbakhul29/backend-framework/api/openapi/v1/generated"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/security"
)

type AuthHandler struct {
	service AuthService
}

func NewHandler(service AuthService) *AuthHandler {
	return &AuthHandler{
		service: service,
	}
}

// PostAuthRegister handles user registration requests
func (h *AuthHandler) PostAuthRegister(w http.ResponseWriter, r *http.Request) {
	var req apiv1.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, r, httpx.ErrBadRequest)
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
		httpx.WriteError(w, r, httpx.ErrValidation)
		return
	}

	user, err := h.service.Register(r.Context(), req.Name, string(req.Email), req.Password)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserAlreadyExists):
			httpx.WriteError(w, r, httpx.ErrConflict)
		default:
			httpx.WriteError(w, r, httpx.ErrInternal)
		}
		return
	}

	resp := apiv1.SuccessRegisterResponse{
		Id:    new(user.ID),
		Name:  new(user.Name),
		Email: new(openapi_types.Email(user.Email)),
	}

	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// PostAuthLogin handles user login requests
func (h *AuthHandler) PostAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req apiv1.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, r, httpx.ErrBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		httpx.WriteError(w, r, httpx.ErrValidation)
		return
	}

	user, tokens, err := h.service.Login(r.Context(), string(req.Email), req.Password)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCredentials):
			httpx.WriteError(w, r, httpx.ErrUnauthorized)
		default:
			httpx.WriteError(w, r, httpx.ErrInternal)
		}
		return
	}

	resp := apiv1.SuccessLoginResponse{
		AccessToken: new(tokens.AccessToken),
		User: &struct {
			Email *openapi_types.Email `json:"email,omitempty"`
			Id    *string              `json:"id,omitempty"`
			Name  *string              `json:"name,omitempty"`
		}{
			Id:    new(user.ID),
			Name:  new(user.Name),
			Email: new(openapi_types.Email(user.Email)),
		},
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetMe handles retrieval of current authenticated user details
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	user, err := h.service.GetMe(r.Context(), principal.UserID.String())
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			httpx.WriteError(w, r, httpx.ErrUnauthorized)
		default:
			httpx.WriteError(w, r, httpx.ErrInternal)
		}
		return
	}

	resp := apiv1.SuccessGetMeResponse{
		Id:    new(user.ID),
		Name:  new(user.Name),
		Email: new(openapi_types.Email(user.Email)),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// PostAuthLogout handles user logout and revokes active session
func (h *AuthHandler) PostAuthLogout(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	err := h.service.Logout(r.Context(), principal.SessionID.String())
	if err != nil {
		httpx.WriteError(w, r, httpx.ErrInternal)
		return
	}

	resp := apiv1.SuccessLogoutResponse{
		Message: new("successfully logged out"),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// PostAuthChangeRole handles request to change user role
func (h *AuthHandler) PostAuthChangeRole(w http.ResponseWriter, r *http.Request) {
	var req apiv1.ChangeRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, r, httpx.ErrBadRequest)
		return
	}

	if req.UserId == "" || req.Role == "" {
		httpx.WriteError(w, r, httpx.ErrValidation)
		return
	}

	err := h.service.ChangeRole(r.Context(), req.UserId, req.Role)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessChangeRoleResponse{
		Message: new("role successfully updated"),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}
