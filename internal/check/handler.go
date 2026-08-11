package check

import (
	"encoding/json"
	"net/http"

	apiv1 "github.com/misbakhul29/learning-chi/api/openapi/v1/generated"
	"github.com/misbakhul29/learning-chi/pkg/security"
)

type CheckHandler struct{}

func NewHandler() *CheckHandler {
	return &CheckHandler{}
}

func (h *CheckHandler) CheckRbac(w http.ResponseWriter, r *http.Request) {
	resp := apiv1.CheckResponse{
		Message: new("RBAC Permission middleware passed successfully!"),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *CheckHandler) CheckScopes(w http.ResponseWriter, r *http.Request) {
	resp := apiv1.CheckResponse{
		Message: new("Data Scopes middleware passed successfully!"),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *CheckHandler) CheckAudit(w http.ResponseWriter, r *http.Request) {
	auditLogged := security.AuditLoggedFromContext(r.Context())
	resp := apiv1.CheckResponse{
		Message:     new("Audit middleware passed successfully!"),
		AuditLogged: new(auditLogged),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *CheckHandler) CheckMfa(w http.ResponseWriter, r *http.Request) {
	resp := apiv1.CheckResponse{
		Message: new("Step-Up MFA middleware passed successfully!"),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
