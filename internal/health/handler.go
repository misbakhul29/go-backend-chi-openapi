package health

import (
	"encoding/json"
	"net/http"
	"time"

	apiv1 "github.com/misbakhul29/backend-framework/api/openapi/v1/generated"
)

type HealthHandler struct{}

func NewHandler() *HealthHandler {
	return &HealthHandler{}
}

// Logika khusus Status
func (h *HealthHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	status := apiv1.Ok
	now := time.Now()

	resp := apiv1.SuccessGetStatusResponse{
		Status:    &status,
		Timestamp: &now,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// GetSystemPermissionCheck handles permission verification check
func (h *HealthHandler) GetSystemPermissionCheck(w http.ResponseWriter, r *http.Request) {
	resp := apiv1.SuccessPermissionCheckResponse{
		Message: new("has debug permission"),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
