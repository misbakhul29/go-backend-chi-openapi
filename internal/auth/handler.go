package auth

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	apiv1 "github.com/misbakhul29/backend-framework/api/openapi/v1/generated"
	"github.com/misbakhul29/backend-framework/pkg/httpx"
	"github.com/misbakhul29/backend-framework/pkg/pointerx"
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

// PostAuthRegister handles user registration requests.
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
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessRegisterResponse{
		Id:    pointerx.String(user.ID),
		Name:  pointerx.String(user.Name),
		Email: (*openapi_types.Email)(pointerx.String(user.Email)),
	}

	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// PostAuthLogin authenticates user credentials, records client metadata, and issues tokens.
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

	ip, ua, dev := ParseClientInfo(r)
	user, tokens, err := h.service.Login(r.Context(), string(req.Email), req.Password, ClientInfo{
		IPAddress: ip,
		UserAgent: ua,
		Device:    dev,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessLoginResponse{
		AccessToken:  pointerx.String(tokens.AccessToken),
		RefreshToken: pointerx.String(tokens.RefreshToken),
		TokenType:    pointerx.String("Bearer"),
		ExpiresIn:    pointerx.Int(tokens.ExpiresIn),
		User: &struct {
			Email *openapi_types.Email `json:"email,omitempty"`
			Id    *string              `json:"id,omitempty"`
			Name  *string              `json:"name,omitempty"`
		}{
			Id:    pointerx.String(user.ID),
			Name:  pointerx.String(user.Name),
			Email: (*openapi_types.Email)(pointerx.String(user.Email)),
		},
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// PostAuthForgotPassword initiates password recovery with anti-enumeration protection.
func (h *AuthHandler) PostAuthForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req apiv1.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, r, httpx.ErrBadRequest)
		return
	}

	if req.Email == "" {
		httpx.WriteError(w, r, httpx.ErrValidation)
		return
	}

	if err := h.service.ForgotPassword(r.Context(), string(req.Email)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessForgotPasswordResponse{
		Message: pointerx.String("If your email is registered, you will receive password reset instructions shortly."),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// PostAuthResetPassword resets an account password using a single-use verification token.
func (h *AuthHandler) PostAuthResetPassword(w http.ResponseWriter, r *http.Request) {
	var req apiv1.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, r, httpx.ErrBadRequest)
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		httpx.WriteError(w, r, httpx.ErrValidation)
		return
	}

	if err := h.service.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessResetPasswordResponse{
		Message: pointerx.String("Password has been successfully reset."),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// PostAuthChangePassword updates the password for the current authenticated user.
func (h *AuthHandler) PostAuthChangePassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	var req apiv1.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, r, httpx.ErrBadRequest)
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		httpx.WriteError(w, r, httpx.ErrValidation)
		return
	}

	revokeOther := false
	if req.RevokeOtherSessions != nil {
		revokeOther = *req.RevokeOtherSessions
	}

	err := h.service.ChangePassword(r.Context(), principal.UserID.String(), req.OldPassword, req.NewPassword, revokeOther, principal.SessionID.String())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessChangePasswordResponse{
		Message: pointerx.String("Password successfully updated."),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// PostAuthRefresh executes Refresh Token Rotation (RTR) and detects token reuse theft.
func (h *AuthHandler) PostAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req apiv1.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, r, httpx.ErrBadRequest)
		return
	}

	if req.RefreshToken == "" {
		httpx.WriteError(w, r, httpx.ErrValidation)
		return
	}

	tokens, err := h.service.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessRefreshResponse{
		AccessToken:  pointerx.String(tokens.AccessToken),
		RefreshToken: pointerx.String(tokens.RefreshToken),
		TokenType:    pointerx.String("Bearer"),
		ExpiresIn:    pointerx.Int(tokens.ExpiresIn),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetAuthSessions lists all active sessions for the current authenticated user.
func (h *AuthHandler) GetAuthSessions(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	sessions, err := h.service.ListActiveSessions(r.Context(), principal.UserID.String(), principal.SessionID.String())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	items := make([]apiv1.SessionItem, len(sessions))
	for i, s := range sessions {
		items[i] = apiv1.SessionItem{
			Id:           s.ID,
			IpAddress:    s.IPAddress,
			UserAgent:    s.UserAgent,
			Device:       s.Device,
			IsCurrent:    s.IsCurrent,
			LastActiveAt: s.LastActiveAt,
			CreatedAt:    s.CreatedAt,
			ExpiresAt:    s.ExpiresAt,
		}
	}

	resp := apiv1.SuccessListSessionsResponse{
		Sessions: &items,
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// DeleteAuthSessionByID revokes a specific active session.
func (h *AuthHandler) DeleteAuthSessionByID(w http.ResponseWriter, r *http.Request, id string) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	if id == "" {
		id = chi.URLParam(r, "id")
	}
	if id == "" {
		httpx.WriteError(w, r, httpx.ErrBadRequest)
		return
	}

	if err := h.service.RevokeSession(r.Context(), id, principal.UserID.String()); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessRevokeSessionResponse{
		Message: pointerx.String("session successfully revoked"),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// DeleteAuthSessions revokes active sessions with support for exclude_current.
func (h *AuthHandler) DeleteAuthSessions(w http.ResponseWriter, r *http.Request, params apiv1.DeleteAuthSessionsParams) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	excludeCurrent := false
	if params.ExcludeCurrent != nil {
		excludeCurrent = *params.ExcludeCurrent
	}
	if r.URL.Query().Get("exclude_current") == "true" {
		excludeCurrent = true
	}

	count, err := h.service.RevokeAllSessions(r.Context(), principal.UserID.String(), principal.SessionID.String(), excludeCurrent)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	revokedCount := int(count)
	resp := apiv1.SuccessRevokeAllSessionsResponse{
		Message:      pointerx.String("sessions successfully revoked"),
		RevokedCount: &revokedCount,
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// GetMe handles retrieval of current authenticated user details.
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	user, err := h.service.GetMe(r.Context(), principal.UserID.String())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessGetMeResponse{
		Id:    pointerx.String(user.ID),
		Name:  pointerx.String(user.Name),
		Email: (*openapi_types.Email)(pointerx.String(user.Email)),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// PostAuthLogout handles user logout and revokes active session.
func (h *AuthHandler) PostAuthLogout(w http.ResponseWriter, r *http.Request) {
	principal, ok := security.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	err := h.service.Logout(r.Context(), principal.SessionID.String())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := apiv1.SuccessLogoutResponse{
		Message: pointerx.String("successfully logged out"),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// PostAuthChangeRole handles request to change user role.
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
		Message: pointerx.String("role successfully updated"),
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

// RegisterRoutes registers all auth routes directly on a Chi router with optional auth middleware.
func (h *AuthHandler) RegisterRoutes(r chi.Router, authMiddleware func(http.Handler) http.Handler) {
	r.Route("/auth", func(r chi.Router) {
		// Public endpoints
		r.Post("/register", h.PostAuthRegister)
		r.Post("/login", h.PostAuthLogin)
		r.Post("/forgot-password", h.PostAuthForgotPassword)
		r.Post("/reset-password", h.PostAuthResetPassword)
		r.Post("/refresh", h.PostAuthRefresh)

		// Protected endpoints
		r.Group(func(r chi.Router) {
			if authMiddleware != nil {
				r.Use(authMiddleware)
			}
			r.Get("/me", h.GetMe)
			r.Post("/logout", h.PostAuthLogout)
			r.Post("/change-password", h.PostAuthChangePassword)
			r.Post("/change-role", h.PostAuthChangeRole)

			r.Get("/sessions", h.GetAuthSessions)
			r.Delete("/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
				id := chi.URLParam(r, "id")
				h.DeleteAuthSessionByID(w, r, id)
			})
			r.Delete("/sessions", func(w http.ResponseWriter, r *http.Request) {
				var params apiv1.DeleteAuthSessionsParams
				if r.URL.Query().Get("exclude_current") == "true" {
					t := true
					params.ExcludeCurrent = &t
				}
				h.DeleteAuthSessions(w, r, params)
			})
		})
	})
}
