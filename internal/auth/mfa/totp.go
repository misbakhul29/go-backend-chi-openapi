package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type TOTPSetupData struct {
	Secret        string   `json:"secret"`
	OtpauthURL    string   `json:"otpauth_url"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type MFAService interface {
	GenerateSecret(issuer, accountName string) (*TOTPSetupData, []string, error)
	VerifyCode(secret, code string) bool
	GenerateRecoveryCodes(count int) ([]string, []string, error)
	VerifyRecoveryCode(code string, storedHashes []string) (bool, int)
}

type DefaultMFAService struct {
	period int64 // typically 30 seconds
	digits int   // typically 6 digits
}

func NewMFAService() *DefaultMFAService {
	return &DefaultMFAService{
		period: 30,
		digits: 6,
	}
}

// GenerateSecret produces a cryptographically random base32 encoded TOTP secret
func (s *DefaultMFAService) GenerateSecret(issuer, accountName string) (*TOTPSetupData, []string, error) {
	rawSecret := make([]byte, 20)
	if _, err := rand.Read(rawSecret); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random secret: %w", err)
	}

	secretB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSecret)

	otpURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		url.PathEscape(issuer),
		url.PathEscape(accountName),
		secretB32,
		url.QueryEscape(issuer),
		s.digits,
		s.period,
	)

	plainCodes, hashedCodes, err := s.GenerateRecoveryCodes(10)
	if err != nil {
		return nil, nil, err
	}

	return &TOTPSetupData{
		Secret:        secretB32,
		OtpauthURL:    otpURL,
		RecoveryCodes: plainCodes,
	}, hashedCodes, nil
}

// GenerateCode calculates the TOTP code for a given timestamp
func (s *DefaultMFAService) GenerateCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}

	counter := uint64(t.Unix() / s.period)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	codeInt := (binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff) % 1000000

	return fmt.Sprintf("%06d", codeInt), nil
}

// VerifyCode checks user-entered code against current time and clock drift window (+/- 1 period)
func (s *DefaultMFAService) VerifyCode(secret, code string) bool {
	cleanCode := strings.TrimSpace(code)
	if len(cleanCode) != s.digits {
		return false
	}

	now := time.Now()
	// Check windows: -1, 0, +1
	for step := -1; step <= 1; step++ {
		targetTime := now.Add(time.Duration(int64(step)*s.period) * time.Second)
		gen, err := s.GenerateCode(secret, targetTime)
		if err == nil && hmac.Equal([]byte(gen), []byte(cleanCode)) {
			return true
		}
	}
	return false
}

// GenerateRecoveryCodes produces single-use backup recovery codes and their SHA-256 hashes
func (s *DefaultMFAService) GenerateRecoveryCodes(count int) ([]string, []string, error) {
	plain := make([]string, count)
	hashes := make([]string, count)

	for i := 0; i < count; i++ {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		code := strings.ToUpper(hex.EncodeToString(b)) // 10 chars hex
		plain[i] = code

		h := sha256.Sum256([]byte(code))
		hashes[i] = hex.EncodeToString(h[:])
	}

	return plain, hashes, nil
}

// VerifyRecoveryCode validates a recovery code against stored hashes
func (s *DefaultMFAService) VerifyRecoveryCode(code string, storedHashes []string) (bool, int) {
	cleanCode := strings.ToUpper(strings.TrimSpace(code))
	h := sha256.Sum256([]byte(cleanCode))
	targetHash := hex.EncodeToString(h[:])

	for idx, stored := range storedHashes {
		if hmac.Equal([]byte(stored), []byte(targetHash)) {
			return true, idx
		}
	}
	return false, -1
}
