package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"gorm.io/gorm"

	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"github.com/misbakhul29/backend-framework/pkg/observer"
	"github.com/misbakhul29/backend-framework/pkg/rabbitx"
)

const (
	EventLoginSuccess    = "AUTH_LOGIN_SUCCESS"
	EventLoginFailure    = "AUTH_LOGIN_FAILURE"
	EventLogout          = "AUTH_LOGOUT"
	EventTokenRefresh    = "AUTH_TOKEN_REFRESH"
	EventTokenReuseAlert = "AUTH_TOKEN_REUSE_DETECTED"
	EventMFASetup        = "AUTH_MFA_SETUP"
	EventMFAVerify       = "AUTH_MFA_VERIFIED"
	EventMFADisabled     = "AUTH_MFA_DISABLED"
	EventSessionRevoked  = "AUTH_SESSION_REVOKED"
	EventOAuthLogin      = "AUTH_OAUTH_LOGIN"
	EventSSOLogin        = "AUTH_SSO_LOGIN"
)

type Event struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	EventType string         `json:"event_type"`
	UserID    *string        `json:"user_id,omitempty"`
	TenantID  *string        `json:"tenant_id,omitempty"`
	IPAddress *string        `json:"ip_address,omitempty"`
	UserAgent *string        `json:"user_agent,omitempty"`
	Status    string         `json:"status"` // SUCCESS, FAILURE, ALERT
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type Service interface {
	Log(ctx context.Context, event Event) error
}

type AuditService struct {
	db     *gorm.DB
	rabbit *amqp.Connection
}

func NewService(db *gorm.DB, rabbit *amqp.Connection) *AuditService {
	return &AuditService{
		db:     db,
		rabbit: rabbit,
	}
}

func (s *AuditService) Log(ctx context.Context, e Event) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}

	// Mask PII in metadata (e.g. passwords, secrets, tokens)
	if e.Metadata != nil {
		masked := make(map[string]any)
		for k, v := range e.Metadata {
			lowerK := strings.ToLower(k)
			if strings.Contains(lowerK, "password") || strings.Contains(lowerK, "secret") || strings.Contains(lowerK, "token") {
				masked[k] = "[REDACTED]"
			} else {
				masked[k] = v
			}
		}
		e.Metadata = masked
	}

	metaJSON, _ := json.Marshal(e.Metadata)
	metaStr := string(metaJSON)

	// Persist to database if db is available
	if s.db != nil {
		record := models.AuditLog{
			ID:        e.ID,
			Timestamp: e.Timestamp,
			EventType: e.EventType,
			UserID:    e.UserID,
			TenantID:  e.TenantID,
			IPAddress: e.IPAddress,
			UserAgent: e.UserAgent,
			Status:    e.Status,
			Metadata:  &metaStr,
			CreatedAt: time.Now(),
		}
		if err := s.db.WithContext(ctx).Create(&record).Error; err != nil {
			observer.Log.Error("failed to write audit log to db", "error", err)
		}
	}

	// Asynchronously publish to RabbitMQ topic exchange if configured
	if s.rabbit != nil {
		routingKey := "audit." + strings.ToLower(e.EventType)
		payload, _ := json.Marshal(e)
		go func() {
			pubCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = rabbitx.Publish(pubCtx, s.rabbit, "audit", routingKey, payload)
		}()
	}

	return nil
}

func EventFromRequest(r *http.Request, eventType, status string, userID *string, meta map[string]any) Event {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.Split(fwd, ",")[0]
	}
	ua := r.UserAgent()

	return Event{
		EventType: eventType,
		Status:    status,
		UserID:    userID,
		IPAddress: &ip,
		UserAgent: &ua,
		Metadata:  meta,
	}
}
