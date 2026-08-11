package security

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrMissingToken         = errors.New("missing bearer token")
	ErrInvalidToken         = errors.New("invalid bearer token")
	ErrInvalidAuthorization = errors.New("invalid authorization header")
)

type JWTClaims struct {
	Subject     uuid.UUID
	TenantID    uuid.UUID
	SessionID   uuid.UUID
	JTI         string
	RolesHash   string
	AMR         []string
	Permissions []string
	Scopes      []string
}

type JWTVerifier interface {
	Verify(ctx context.Context, token string) (*JWTClaims, error)
}

type DummyJWTVerifier struct{}

func (v *DummyJWTVerifier) Verify(ctx context.Context, token string) (*JWTClaims, error) {
	if token == "my-secret-token" {
		return &JWTClaims{
			Subject:     uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			TenantID:    uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			SessionID:   uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			JTI:         "dummy-jti",
			RolesHash:   "dummy-hash",
			AMR:         []string{"pwd"},
			Permissions: []string{"check:rbac:read"},
			Scopes:      []string{"check:scopes:read"},
		}, nil
	} else if token == "mfa-token" {
		return &JWTClaims{
			Subject:     uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			TenantID:    uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			SessionID:   uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			JTI:         "mfa-jti",
			RolesHash:   "mfa-hash",
			AMR:         []string{"pwd", "mfa"},
			Permissions: []string{"check:rbac:read"},
			Scopes:      []string{"check:scopes:read"},
		}, nil
	} else if token == "no-permission-token" {
		return &JWTClaims{
			Subject:     uuid.MustParse("00000000-0000-0000-0000-000000000009"),
			TenantID:    uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			SessionID:   uuid.MustParse("00000000-0000-0000-0000-000000000003"),
			JTI:         "no-permission-jti",
			RolesHash:   "no-permission-hash",
			AMR:         []string{"pwd"},
			Permissions: []string{}, // Empty permissions
			Scopes:      []string{}, // Empty scopes
		}, nil
	}
	return nil, ErrInvalidToken
}

type JWTService struct {
	verifier JWTVerifier
}

func NewJWTService(verifier JWTVerifier) *JWTService {
	return &JWTService{
		verifier: verifier,
	}
}

func (s *JWTService) Authenticate(ctx context.Context, token string) (*Principal, error) {
	claims, err := s.verifier.Verify(ctx, token)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return &Principal{
		UserID:      claims.Subject,
		TenantID:    claims.TenantID,
		SessionID:   claims.SessionID,
		JTI:         claims.JTI,
		RolesHash:   claims.RolesHash,
		AMR:         claims.AMR,
		Permissions: claims.Permissions,
		Scopes:      claims.Scopes,
	}, nil
}

func extractBearerToken(value string) (string, error) {
	if value == "" {
		return "", ErrMissingToken
	}

	parts := strings.Fields(value)

	if len(parts) != 2 {
		return "", ErrInvalidAuthorization
	}

	if strings.ToLower(parts[0]) != "bearer" {
		return "", ErrInvalidAuthorization
	}

	if parts[1] == "" {
		return "", ErrInvalidAuthorization
	}

	return parts[1], nil
}
