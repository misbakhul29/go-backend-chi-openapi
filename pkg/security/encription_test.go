package security

import (
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/misbakhul29/backend-framework/config"
)

func TestNewEncryptor_EmptyKey(t *testing.T) {
	testCases := []string{"", "   ", "\t\n"}
	for _, key := range testCases {
		_, err := NewEncryptor(key)
		if !errors.Is(err, ErrEmptyEncryptionKey) {
			t.Errorf("NewEncryptor(%q) error = %v; want ErrEmptyEncryptionKey", key, err)
		}
	}
}

func TestNewEncryptorFromBytes_InvalidLength(t *testing.T) {
	invalidKeys := [][]byte{
		{},
		make([]byte, 16),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	}

	for _, key := range invalidKeys {
		_, err := NewEncryptorFromBytes(key)
		if err == nil {
			t.Errorf("expected error for key length %d, got nil", len(key))
		}
	}
}

func TestEncryptor_RoundTrip(t *testing.T) {
	testKeys := []struct {
		name string
		key  string
	}{
		{
			name: "64-char valid hex key",
			key:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name: "arbitrary passphrase",
			key:  "my-super-secret-production-passphrase-2026!",
		},
		{
			name: "short string",
			key:  "simple-key",
		},
	}

	testPlaintexts := []string{
		"Hello, World!",
		"",
		"Sensitive TOTP Secret: JBSWY3DPEHPK3PXP",
		"Special characters: !@#$%^&*()_+{}[]:;'<>?,./~` and Unicode 🚀🔑🔒",
	}

	for _, tk := range testKeys {
		t.Run(tk.name, func(t *testing.T) {
			enc, err := NewEncryptor(tk.key)
			if err != nil {
				t.Fatalf("failed to create encryptor: %v", err)
			}

			for _, pt := range testPlaintexts {
				ct, err := enc.Encrypt(pt)
				if err != nil {
					t.Fatalf("failed to encrypt %q: %v", pt, err)
				}

				decrypted, err := enc.Decrypt(ct)
				if err != nil {
					t.Fatalf("failed to decrypt %q: %v", ct, err)
				}

				if decrypted != pt {
					t.Errorf("decrypted %q != original %q", decrypted, pt)
				}
			}
		})
	}
}

func TestEncryptWithKey_Decoupled(t *testing.T) {
	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()
	config.Cfg = nil

	os.Unsetenv("NODE_ENV")

	key := "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123"
	plainText := "decoupled secret message"

	ct, err := EncryptWithKey(key, plainText)
	if err != nil {
		t.Fatalf("EncryptWithKey failed when Cfg is nil: %v", err)
	}

	pt, err := DecryptWithKey(key, ct)
	if err != nil {
		t.Fatalf("DecryptWithKey failed when Cfg is nil: %v", err)
	}

	if pt != plainText {
		t.Errorf("got %q, want %q", pt, plainText)
	}
}

func TestEncryptor_TamperedCiphertext(t *testing.T) {
	enc, err := NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	ctHex, err := enc.Encrypt("authentic payload")
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	ctBytes, err := hex.DecodeString(ctHex)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}

	// Tamper with the last byte (auth tag)
	ctBytes[len(ctBytes)-1] ^= 0xFF
	tamperedHex := hex.EncodeToString(ctBytes)

	_, err = enc.Decrypt(tamperedHex)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed on tampered ciphertext, got %v", err)
	}
}

func TestEncryptor_MalformedHex(t *testing.T) {
	enc, err := NewEncryptor("passphrase")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	_, err = enc.Decrypt("this is not hex!")
	if !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("expected ErrInvalidCiphertext, got %v", err)
	}
}

func TestEncryptor_ShortCiphertext(t *testing.T) {
	enc, err := NewEncryptor("passphrase")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Nonce is 12 bytes + Overhead is 16 bytes = minimum 28 bytes (56 hex characters)
	_, err = enc.Decrypt("aabbccdd")
	if !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("expected ErrCiphertextTooShort, got %v", err)
	}
}

func TestEncryptor_NonceRandomness(t *testing.T) {
	enc, err := NewEncryptor("same-key-for-all")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	plainText := "confidential data"
	seen := make(map[string]bool)

	for i := 0; i < 10; i++ {
		ct, err := enc.Encrypt(plainText)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}
		if seen[ct] {
			t.Fatalf("detected identical ciphertext on iteration %d, nonce must be unique", i)
		}
		seen[ct] = true
	}
}

func TestPackageEncrypt_BackwardCompatibility(t *testing.T) {
	originalCfg := config.Cfg
	defer func() { config.Cfg = originalCfg }()

	// 1. With config.Cfg set
	config.Cfg = &config.Env{
		EncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	ct, err := Encrypt("test message")
	if err != nil {
		t.Fatalf("Encrypt failed with config.Cfg: %v", err)
	}

	pt, err := Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt failed with config.Cfg: %v", err)
	}
	if pt != "test message" {
		t.Errorf("got %q, want 'test message'", pt)
	}

	// 2. With config.Cfg == nil, but NODE_ENV=test
	config.Cfg = nil
	os.Setenv("NODE_ENV", "test")
	defer os.Unsetenv("NODE_ENV")

	ct2, err := Encrypt("test in test env")
	if err != nil {
		t.Fatalf("Encrypt failed in test env with nil Cfg: %v", err)
	}
	pt2, err := Decrypt(ct2)
	if err != nil {
		t.Fatalf("Decrypt failed in test env with nil Cfg: %v", err)
	}
	if pt2 != "test in test env" {
		t.Errorf("got %q, want 'test in test env'", pt2)
	}

	// 3. With config.Cfg == nil, and NODE_ENV unset
	os.Unsetenv("NODE_ENV")
	_, err = Encrypt("unconfigured message")
	if err == nil {
		t.Errorf("expected error when encryption key is not configured, got nil")
	}
}
