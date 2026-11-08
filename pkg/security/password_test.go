package security

import (
	"testing"
)

func TestValidateEmail(t *testing.T) {
	validEmails := []string{
		"user@example.com",
		"first.last@domain.co.id",
		"user+tag@sub.domain.org",
		"admin_123@company.io",
	}

	for _, email := range validEmails {
		if err := ValidateEmail(email); err != nil {
			t.Errorf("expected email %q to be valid, got: %v", email, err)
		}
	}

	invalidEmails := []string{
		"",
		"   ",
		"plainaddress",
		"@missingusername.com",
		"username@.com",
		"username@com",
		"user space@domain.com",
	}

	for _, email := range invalidEmails {
		if err := ValidateEmail(email); err == nil {
			t.Errorf("expected email %q to be invalid, got nil error", email)
		}
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	validPasswords := []string{
		"P@ssw0rd123!",
		"Secure#Pass2026",
		"Str0ng&Complex!",
	}

	for _, pass := range validPasswords {
		if err := ValidatePasswordStrength(pass); err != nil {
			t.Errorf("expected password %q to be valid, got: %v", pass, err)
		}
	}

	invalidCases := []struct {
		password string
		expected error
	}{
		{"Short1!", ErrPasswordTooShort},
		{"nouppercase123!", ErrPasswordNoUpper},
		{"NOLOWERCASE123!", ErrPasswordNoLower},
		{"NoDigitsHere!?", ErrPasswordNoDigit},
		{"NoSymbols12345", ErrPasswordNoSymbol},
	}

	for _, tc := range invalidCases {
		err := ValidatePasswordStrength(tc.password)
		if err == nil {
			t.Errorf("expected password %q to fail with %v, got nil", tc.password, tc.expected)
		}
	}
}

func TestDummyVerifyPassword(t *testing.T) {
	// DummyVerifyPassword should execute without panicking
	DummyVerifyPassword("arbitrary-password-check")
}
