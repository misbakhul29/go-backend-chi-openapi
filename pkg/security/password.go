package security

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

var (
	ErrInvalidEmailFormat = errors.New("invalid email format")
	ErrPasswordTooShort   = errors.New("password must be at least 8 characters")
	ErrPasswordTooLong    = errors.New("password must not exceed 128 characters")
	ErrPasswordNoUpper    = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLower    = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoDigit    = errors.New("password must contain at least one number")
	ErrPasswordNoSymbol   = errors.New("password must contain at least one special character")

	// Standard RFC 5322 compliant regex for email format validation
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
)

// ValidateEmail checks email length and conformity to RFC 5322.
func ValidateEmail(email string) error {
	trimmed := strings.TrimSpace(email)
	if len(trimmed) == 0 || len(trimmed) > 254 {
		return ErrInvalidEmailFormat
	}
	if !emailRegex.MatchString(trimmed) {
		return ErrInvalidEmailFormat
	}
	return nil
}

// ValidatePasswordStrength enforces complexity: >=8 and <=128 characters, upper, lower, digit, and symbol.
func ValidatePasswordStrength(password string) error {
	length := len(password)
	if length < 8 {
		return ErrPasswordTooShort
	}
	if length > 128 {
		return ErrPasswordTooLong
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSymbol = true
		}
	}

	if !hasUpper {
		return ErrPasswordNoUpper
	}
	if !hasLower {
		return ErrPasswordNoLower
	}
	if !hasDigit {
		return ErrPasswordNoDigit
	}
	if !hasSymbol {
		return ErrPasswordNoSymbol
	}

	return nil
}
