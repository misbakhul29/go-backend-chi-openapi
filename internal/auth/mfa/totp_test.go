package mfa

import (
	"testing"
	"time"
)

func TestTOTP_GenerateAndVerify(t *testing.T) {
	svc := NewMFAService()

	setupData, hashedCodes, err := svc.GenerateSecret("Backend Framework", "user@test.org")
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	if setupData.Secret == "" || setupData.OtpauthURL == "" || len(setupData.RecoveryCodes) != 10 {
		t.Fatalf("unexpected setup data: %+v", setupData)
	}

	if len(hashedCodes) != 10 {
		t.Fatalf("expected 10 hashed recovery codes, got %d", len(hashedCodes))
	}

	// Calculate valid code for right now
	code, err := svc.GenerateCode(setupData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate code: %v", err)
	}

	if !svc.VerifyCode(setupData.Secret, code) {
		t.Fatal("expected TOTP code to verify successfully")
	}

	// Verify clock drift window: 25 seconds ago should pass (-1 step window)
	driftCode, err := svc.GenerateCode(setupData.Secret, time.Now().Add(-25*time.Second))
	if err != nil {
		t.Fatalf("failed to generate drift code: %v", err)
	}
	if !svc.VerifyCode(setupData.Secret, driftCode) {
		t.Fatal("expected drift code to verify within window")
	}

	// Invalid code should fail
	if svc.VerifyCode(setupData.Secret, "000000") && code != "000000" {
		t.Fatal("expected bogus code to fail")
	}
}

func TestRecoveryCodes(t *testing.T) {
	svc := NewMFAService()

	plainCodes, hashedCodes, err := svc.GenerateRecoveryCodes(5)
	if err != nil {
		t.Fatalf("failed to generate recovery codes: %v", err)
	}

	// Verify valid recovery code
	valid, idx := svc.VerifyRecoveryCode(plainCodes[2], hashedCodes)
	if !valid || idx != 2 {
		t.Fatalf("expected recovery code at index 2 to match, got valid=%v, idx=%d", valid, idx)
	}

	// Verify invalid recovery code
	invalid, _ := svc.VerifyRecoveryCode("BADCODE123", hashedCodes)
	if invalid {
		t.Fatal("expected invalid recovery code to fail")
	}
}
