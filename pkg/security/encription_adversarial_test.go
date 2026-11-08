package security

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestAdversarial_NewEncryptor_EmptyAndWhitespaceKeys tests that empty or whitespace-only keys
// are strictly rejected with ErrEmptyEncryptionKey.
func TestAdversarial_NewEncryptor_EmptyAndWhitespaceKeys(t *testing.T) {
	whitespaceCases := []struct {
		name string
		key  string
	}{
		{"empty string", ""},
		{"single space", " "},
		{"multiple spaces", "    "},
		{"tab character", "\t"},
		{"multiple tabs", "\t\t\t"},
		{"newline", "\n"},
		{"carriage return and newline", "\r\n"},
		{"mixed whitespace", " \t \r\n \v \f "},
	}

	for _, tc := range whitespaceCases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := NewEncryptor(tc.key)
			if enc != nil {
				t.Errorf("expected nil encryptor for key %q, got %+v", tc.key, enc)
			}
			if !errors.Is(err, ErrEmptyEncryptionKey) {
				t.Errorf("NewEncryptor(%q) error = %v; want ErrEmptyEncryptionKey", tc.key, err)
			}
		})
	}
}

// TestAdversarial_NewEncryptor_KeyVariations verifies handling of truncated, odd-length,
// arbitrary, unicode, and extreme length passphrases.
func TestAdversarial_NewEncryptor_KeyVariations(t *testing.T) {
	keyVariations := []struct {
		name string
		key  string
	}{
		{"single character", "x"},
		{"two characters", "ab"},
		{"short passphrase", "secret"},
		{"15 chars", "123456789012345"},
		{"16 chars", "1234567890123456"},
		{"31 chars", "1234567890123456789012345678901"},
		{"63 chars (odd hex length)", strings.Repeat("a", 63)},
		{"64 chars valid hex", strings.Repeat("f", 64)},
		{"64 chars non-hex", strings.Repeat("z", 64)},
		{"65 chars", strings.Repeat("b", 65)},
		{"unicode with emojis", "p@ssw0rd🔑🔒🚀-sécure-2026-日本語-العربية"},
		{"10KB passphrase", strings.Repeat("passphrase-chunk-1234567890-", 350)},
		{"1MB passphrase", strings.Repeat("A", 1024*1024)},
	}

	plaintexts := []string{
		"",
		"small payload",
		"Medium payload: " + strings.Repeat("payload-content-", 50),
	}

	for _, tc := range keyVariations {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := NewEncryptor(tc.key)
			if err != nil {
				t.Fatalf("NewEncryptor failed for %s: %v", tc.name, err)
			}

			for _, pt := range plaintexts {
				ct, err := enc.Encrypt(pt)
				if err != nil {
					t.Fatalf("Encrypt failed for key %s with pt %q: %v", tc.name, pt, err)
				}

				decrypted, err := enc.Decrypt(ct)
				if err != nil {
					t.Fatalf("Decrypt failed for key %s with ct %q: %v", tc.name, ct, err)
				}

				if decrypted != pt {
					t.Fatalf("decrypted mismatch: got %q, want %q", decrypted, pt)
				}
			}
		})
	}
}

// TestAdversarial_NewEncryptorFromBytes_Lengths verifies that NewEncryptorFromBytes
// strictly rejects any byte slice whose length is not exactly 32 bytes.
func TestAdversarial_NewEncryptorFromBytes_Lengths(t *testing.T) {
	testLengths := []int{0, 1, 2, 8, 15, 16, 24, 31, 33, 48, 64, 128}

	for _, l := range testLengths {
		b := make([]byte, l)
		enc, err := NewEncryptorFromBytes(b)
		if enc != nil {
			t.Errorf("expected nil encryptor for length %d, got %+v", l, enc)
		}
		if err == nil {
			t.Errorf("expected error for key byte length %d, got nil", l)
		}
	}

	// Exactly 32 bytes must succeed
	valid32 := make([]byte, 32)
	enc, err := NewEncryptorFromBytes(valid32)
	if err != nil {
		t.Fatalf("unexpected error for 32-byte key: %v", err)
	}
	if enc == nil {
		t.Fatal("expected non-nil encryptor for 32-byte key")
	}
}

// TestAdversarial_Encryptor_ConcurrentStress stresses a single shared GCMEncryptor
// across 60+ concurrent goroutines performing encryption and decryption simultaneously under -race.
func TestAdversarial_Encryptor_ConcurrentStress(t *testing.T) {
	const goroutines = 64
	const iterations = 50

	enc, err := NewEncryptor("super-concurrent-stress-key-32bytes-hex-pad")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)

	errChan := make(chan error, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		go func(routineID int) {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				// Vary payload sizes across iterations
				payloadLen := (routineID*7 + i*13) % 2048
				plainText := fmt.Sprintf("goroutine-%d-iter-%d-padding-%s", routineID, i, strings.Repeat("x", payloadLen))

				ct, err := enc.Encrypt(plainText)
				if err != nil {
					errChan <- fmt.Errorf("goroutine %d iter %d encrypt failed: %w", routineID, i, err)
					return
				}

				decrypted, err := enc.Decrypt(ct)
				if err != nil {
					errChan <- fmt.Errorf("goroutine %d iter %d decrypt failed: %w", routineID, i, err)
					return
				}

				if decrypted != plainText {
					errChan <- fmt.Errorf("goroutine %d iter %d plaintext mismatch", routineID, i)
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent stress error: %v", err)
	}
}

// TestAdversarial_EncryptWithKey_ConcurrentStress verifies concurrent one-off EncryptWithKey and DecryptWithKey.
func TestAdversarial_EncryptWithKey_ConcurrentStress(t *testing.T) {
	const goroutines = 50
	const iterations = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)

	errChan := make(chan error, goroutines*iterations)

	for g := 0; g < goroutines; g++ {
		go func(routineID int) {
			defer wg.Done()
			key := fmt.Sprintf("dynamic-passphrase-for-goroutine-%d", routineID)

			for i := 0; i < iterations; i++ {
				plainText := fmt.Sprintf("secret-routine-%d-iteration-%d", routineID, i)
				ct, err := EncryptWithKey(key, plainText)
				if err != nil {
					errChan <- fmt.Errorf("routine %d encrypt error: %w", routineID, err)
					return
				}

				decrypted, err := DecryptWithKey(key, ct)
				if err != nil {
					errChan <- fmt.Errorf("routine %d decrypt error: %w", routineID, err)
					return
				}

				if decrypted != plainText {
					errChan <- fmt.Errorf("routine %d mismatch: got %q, want %q", routineID, decrypted, plainText)
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("concurrent EncryptWithKey error: %v", err)
	}
}

// TestAdversarial_BitFlipping_IntegrityCheck verifies that flipping every single bit
// in a valid ciphertext causes Decrypt to return ErrDecryptionFailed without panicking.
func TestAdversarial_BitFlipping_IntegrityCheck(t *testing.T) {
	enc, err := NewEncryptor("adversarial-bit-flip-test-key-2026")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	originalPlaintext := "The quick brown fox jumps over the lazy dog 1234567890!@#$%^&*()_+~"
	ctHex, err := enc.Encrypt(originalPlaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	ctBytes, err := hex.DecodeString(ctHex)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}

	// Test bit flips on every byte and every bit
	for byteIdx := 0; byteIdx < len(ctBytes); byteIdx++ {
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			// Flip bit
			ctBytes[byteIdx] ^= (1 << bitIdx)
			mutatedHex := hex.EncodeToString(ctBytes)

			decrypted, decErr := enc.Decrypt(mutatedHex)

			// Decrypt must not panic and must return ErrDecryptionFailed
			if decErr == nil {
				t.Fatalf("SECURITY VIOLATION: Decrypt succeeded on bit-flipped ciphertext at byte %d bit %d! Decrypted: %q",
					byteIdx, bitIdx, decrypted)
			}
			if !errors.Is(decErr, ErrDecryptionFailed) {
				t.Errorf("byte %d bit %d: expected ErrDecryptionFailed, got %v", byteIdx, bitIdx, decErr)
			}

			// Restore bit for next test
			ctBytes[byteIdx] ^= (1 << bitIdx)
		}
	}
}

// TestAdversarial_TruncatedCiphertext_NoPanics verifies that truncated ciphertexts
// below the minimum required length (nonce 12 + tag 16 = 28 bytes = 56 hex chars)
// fail safely with ErrCiphertextTooShort without panicking.
func TestAdversarial_TruncatedCiphertext_NoPanics(t *testing.T) {
	enc, err := NewEncryptor("adversarial-truncation-test-key")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	originalPlaintext := "sensitive data to be truncated"
	ctHex, err := enc.Encrypt(originalPlaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	ctBytes, err := hex.DecodeString(ctHex)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}

	// Any length from 0 to 27 bytes is too short (< 28 bytes)
	for length := 0; length < 28 && length <= len(ctBytes); length++ {
		truncatedBytes := ctBytes[:length]
		truncatedHex := hex.EncodeToString(truncatedBytes)

		decrypted, decErr := enc.Decrypt(truncatedHex)
		if decErr == nil {
			t.Fatalf("expected error on truncated length %d, got decrypted %q", length, decrypted)
		}
		if !errors.Is(decErr, ErrCiphertextTooShort) {
			t.Errorf("length %d: expected ErrCiphertextTooShort, got %v", length, decErr)
		}
	}
}

// TestAdversarial_CorruptedCiphertext_HexAndGarbage verifies that malformed hex strings,
// odd-length hex strings, random binary noise, and non-hex characters all return ErrInvalidCiphertext
// without panicking.
func TestAdversarial_CorruptedCiphertext_HexAndGarbage(t *testing.T) {
	enc, err := NewEncryptor("adversarial-garbage-test-key")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	corruptedCases := []struct {
		name        string
		input       string
		expectedErr error
	}{
		{"odd length hex (1 char)", "a", ErrInvalidCiphertext},
		{"odd length hex (3 chars)", "abc", ErrInvalidCiphertext},
		{"odd length hex (57 chars)", strings.Repeat("a", 57), ErrInvalidCiphertext},
		{"non-hex letters", "not-a-valid-hex-string-at-all-xyz123456789", ErrInvalidCiphertext},
		{"hex with invalid character 'g'", "0123456789abcdefg0123456789abcdef0123456789abcdef0123456789abcdef", ErrInvalidCiphertext},
		{"hex with spaces", "01 23 45 67 89 ab cd ef", ErrInvalidCiphertext},
		{"unicode emoji string", "🔑🔒🚀🔐🛡️", ErrInvalidCiphertext},
		{"control characters and null bytes", "\x00\x01\x02\x03\x04\x05\x06\x07", ErrInvalidCiphertext},
	}

	for _, tc := range corruptedCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enc.Decrypt(tc.input)
			if err == nil {
				t.Fatalf("expected error for corrupted input %q, got nil", tc.input)
			}
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("input %q: got error %v, want %v", tc.input, err, tc.expectedErr)
			}
		})
	}
}

// TestAdversarial_CrossKey_DecryptionFailure verifies that ciphertext encrypted with Key A
// cannot be decrypted with Key B, failing with ErrDecryptionFailed without panicking.
func TestAdversarial_CrossKey_DecryptionFailure(t *testing.T) {
	encA, err := NewEncryptor("primary-secret-key-alpha-12345")
	if err != nil {
		t.Fatalf("failed to create encA: %v", err)
	}

	encB, err := NewEncryptor("secondary-secret-key-beta-67890")
	if err != nil {
		t.Fatalf("failed to create encB: %v", err)
	}

	ctA, err := encA.Encrypt("secret message from agent A")
	if err != nil {
		t.Fatalf("failed to encrypt with encA: %v", err)
	}

	decrypted, err := encB.Decrypt(ctA)
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: Key B decrypted ciphertext from Key A: %q", decrypted)
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

// TestAdversarial_RandomNoiseDecryption verifies that random noise of valid length
// fails decryption safely without panics.
func TestAdversarial_RandomNoiseDecryption(t *testing.T) {
	enc, err := NewEncryptor("random-noise-test-key")
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	for i := 0; i < 50; i++ {
		// Minimum 28 bytes, up to 256 bytes of pure random noise
		noiseLen := 28 + (i * 4)
		noise := make([]byte, noiseLen)
		if _, err := rand.Read(noise); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}

		noiseHex := hex.EncodeToString(noise)
		_, err := enc.Decrypt(noiseHex)
		if err == nil {
			t.Fatalf("SECURITY VIOLATION: random noise decrypted successfully on iteration %d", i)
		}
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Errorf("iteration %d: expected ErrDecryptionFailed, got %v", i, err)
		}
	}
}
