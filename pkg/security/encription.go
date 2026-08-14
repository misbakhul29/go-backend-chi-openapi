package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/misbakhul29/backend-framework/config"
)

// getEncryptionKey retrieves and standardizes the 32-byte key from config.Cfg.EncryptionKey.
// If it's hex-encoded and 32 bytes, we decode it. Otherwise, we hash the raw string using SHA-256 to get a 32-byte key.
func getEncryptionKey() []byte {
	keyStr := config.Cfg.EncryptionKey
	if len(keyStr) == 64 {
		if key, err := hex.DecodeString(keyStr); err == nil && len(key) == 32 {
			return key
		}
	}
	// Fallback/hash to ensure exactly 32 bytes
	hash := sha256.Sum256([]byte(keyStr))
	return hash[:]
}

// Encrypt encrypts plaintext to a hex-encoded cipher text using AES-256-GCM.
func Encrypt(plainText string) (string, error) {
	key := getEncryptionKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends the cipher text to nonce, so we get nonce + cipherText
	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return hex.EncodeToString(cipherText), nil
}

// Decrypt decrypts hex-encoded ciphertext back to plaintext using AES-256-GCM.
func Decrypt(cipherTextHex string) (string, error) {
	key := getEncryptionKey()
	cipherText, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext format (not hex): %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, actualCipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, actualCipherText, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return string(plainText), nil
}
