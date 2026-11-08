package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/misbakhul29/backend-framework/config"
)

var (
	ErrEmptyEncryptionKey = errors.New("encryption key cannot be empty")
	ErrInvalidCiphertext  = errors.New("invalid ciphertext format: not valid hex")
	ErrCiphertextTooShort = errors.New("ciphertext too short to contain nonce and tag")
	ErrDecryptionFailed   = errors.New("failed to decrypt ciphertext: integrity check failed")
)

const fallbackTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type Encryptor interface {
	Encrypt(plainText string) (string, error)
	Decrypt(cipherTextHex string) (string, error)
}

type GCMEncryptor struct {
	gcm cipher.AEAD
}

func ParseKey(keyStr string) []byte {
	if len(keyStr) == 64 {
		if key, err := hex.DecodeString(keyStr); err == nil && len(key) == 32 {
			return key
		}
	}
	hash := sha256.Sum256([]byte(keyStr))
	return hash[:]
}

func NewEncryptor(keyStr string) (*GCMEncryptor, error) {
	if strings.TrimSpace(keyStr) == "" {
		return nil, ErrEmptyEncryptionKey
	}
	keyBytes := ParseKey(keyStr)
	return NewEncryptorFromBytes(keyBytes)
}

func NewEncryptorFromBytes(key []byte) (*GCMEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}
	return &GCMEncryptor{gcm: gcm}, nil
}

func (e *GCMEncryptor) Encrypt(plainText string) (string, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	cipherText := e.gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return hex.EncodeToString(cipherText), nil
}

func (e *GCMEncryptor) Decrypt(cipherTextHex string) (string, error) {
	cipherText, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return "", ErrInvalidCiphertext
	}

	nonceSize := e.gcm.NonceSize()
	if len(cipherText) < nonceSize+e.gcm.Overhead() {
		return "", ErrCiphertextTooShort
	}

	nonce, actualCipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := e.gcm.Open(nil, nonce, actualCipherText, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plainText), nil
}

func EncryptWithKey(key string, plainText string) (string, error) {
	enc, err := NewEncryptor(key)
	if err != nil {
		return "", err
	}
	return enc.Encrypt(plainText)
}

func DecryptWithKey(key string, cipherTextHex string) (string, error) {
	enc, err := NewEncryptor(key)
	if err != nil {
		return "", err
	}
	return enc.Decrypt(cipherTextHex)
}

func resolveGlobalKey() (string, error) {
	if config.Cfg != nil && strings.TrimSpace(config.Cfg.EncryptionKey) != "" {
		return config.Cfg.EncryptionKey, nil
	}
	if os.Getenv("NODE_ENV") == "test" {
		return fallbackTestKey, nil
	}
	return "", errors.New("encryption key not configured")
}

func Encrypt(plainText string) (string, error) {
	key, err := resolveGlobalKey()
	if err != nil {
		return "", err
	}
	return EncryptWithKey(key, plainText)
}

func Decrypt(cipherTextHex string) (string, error) {
	key, err := resolveGlobalKey()
	if err != nil {
		return "", err
	}
	return DecryptWithKey(key, cipherTextHex)
}
