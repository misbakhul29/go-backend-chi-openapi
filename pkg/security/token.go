package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenConfig holds JWT signing configuration.
type TokenConfig struct {
	Secret     []byte
	AccessTTL  time.Duration // default: 15 minutes
	RefreshTTL time.Duration // default: 7 days
}

// IssuedTokens is the result of a successful token issuance.
type IssuedTokens struct {
	AccessToken  string
	RefreshToken string // opaque hex token
	JTI          string // jti of the access token (for refresh_tokens table)
	ExpiresIn    int    // seconds until access token expiry
}

type accessClaims struct {
	jwt.RegisteredClaims
	TenantID    string   `json:"tid"`
	AMR         []string `json:"amr"`
	Permissions []string `json:"permissions,omitempty"`
}

// IssueTokens creates a signed JWT access token and an opaque refresh token.
func IssueTokens(cfg TokenConfig, userID, tenantID string, amr []string, permissions []string) (*IssuedTokens, error) {
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = 7 * 24 * time.Hour
	}

	now := time.Now()
	jti := uuid.NewString()

	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.AccessTTL)),
		},
		TenantID:    tenantID,
		AMR:         amr,
		Permissions: permissions,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshToken, err := generateOpaqueToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	return &IssuedTokens{
		AccessToken:  signed,
		RefreshToken: refreshToken,
		JTI:          jti,
		ExpiresIn:    int(cfg.AccessTTL.Seconds()),
	}, nil
}

// generateOpaqueToken generates a cryptographically random hex token of n bytes.
func generateOpaqueToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns a SHA-256 hex hash of a token — used for secure storage.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// GenerateBackupCodes generates a list of secure, random backup codes in XXXX-XXXX format.
func GenerateBackupCodes(count int) ([]string, error) {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // avoid confusing characters like O, 0, I, 1
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		for j := range b {
			b[j] = chars[int(b[j])%len(chars)]
		}
		codes[i] = fmt.Sprintf("%s-%s", string(b[0:4]), string(b[4:8]))
	}
	return codes, nil
}
