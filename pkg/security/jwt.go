package security

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
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
}

type JWTVerifier interface {
	Verify(ctx context.Context, token string) (*JWTClaims, error)
}

type JWTVerifierImpl struct {
	secret []byte
}

func NewJWTVerifier(secret []byte) *JWTVerifierImpl {
	return &JWTVerifierImpl{secret: secret}
}

func (v *JWTVerifierImpl) Verify(ctx context.Context, tokenStr string) (*JWTClaims, error) {


	token, err := jwt.ParseWithClaims(tokenStr, &accessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*accessClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	subUUID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, ErrInvalidToken
	}

	tenantUUID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return nil, ErrInvalidToken
	}

	var sessionUUID uuid.UUID
	if claims.ID != "" {
		if u, err := uuid.Parse(claims.ID); err == nil {
			sessionUUID = u
		}
	}

	return &JWTClaims{
		Subject:     subUUID,
		TenantID:    tenantUUID,
		SessionID:   sessionUUID,
		JTI:         claims.ID,
		RolesHash:   "",
		AMR:         claims.AMR,
		Permissions: claims.Permissions,
	}, nil
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
