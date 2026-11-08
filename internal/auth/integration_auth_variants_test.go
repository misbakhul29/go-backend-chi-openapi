package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/misbakhul29/backend-framework/config"
	"github.com/misbakhul29/backend-framework/internal/auth/mfa"
	"github.com/misbakhul29/backend-framework/internal/auth/oauth"
	"github.com/misbakhul29/backend-framework/internal/auth/sso"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
)

type mockOAuthProvider struct {
	name    string
	profile *oauth.UserProfile
}

func (m *mockOAuthProvider) Name() string { return m.name }
func (m *mockOAuthProvider) GetAuthURL(state string, opts ...oauth.AuthOption) (string, error) {
	return "https://auth.mock.com/authorize?state=" + state, nil
}
func (m *mockOAuthProvider) Exchange(ctx context.Context, code string, opts ...oauth.ExchangeOption) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "mock-token"}, nil
}
func (m *mockOAuthProvider) FetchUserProfile(ctx context.Context, token *oauth2.Token) (*oauth.UserProfile, error) {
	return m.profile, nil
}

func setupTestAuthSuite(t *testing.T) (*AuthHandler, *AuthServiceImpl, *oauth.Registry, *gorm.DB) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	err = db.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.Permission{},
		&models.Account{},
		&models.Session{},
		&models.RefreshToken{},
		&models.MfaBackupCode{},
		&models.Verification{},
		&models.AuditLog{},
	)
	if err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	role := &models.Role{
		ID:        uuid.NewString(),
		Name:      models.DefaultRole,
		IsDefault: true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	db.FirstOrCreate(role, "name = ?", models.DefaultRole)

	repo := NewRepository(db)
	jwtCfg := config.JWT{
		Secret:     "super-secret-key-for-testing-only-12345",
		AccessTTL:  900,
		RefreshTTL: 86400,
	}

	svc := NewService(repo, db, nil, jwtCfg)
	handler := NewHandler(svc)

	oauthReg := oauth.NewRegistry()
	handler.SetOAuthRegistry(oauthReg)

	samlSvc, _ := sso.NewSAMLService(sso.SAMLSPConfig{
		EntityID:  "https://example.com/metadata",
		ACSURL:    "https://example.com/acs",
		IdPSSOURL: "https://idp.example.com/sso",
	})
	handler.SetSAMLService(samlSvc)

	return handler, svc, oauthReg, db
}

func TestIntegration_OAuthFlow(t *testing.T) {
	handler, _, reg, _ := setupTestAuthSuite(t)

	mockGoogle := &mockOAuthProvider{
		name: "google",
		profile: &oauth.UserProfile{
			ProviderID:    "google",
			AccountID:     "google-sub-123",
			Email:         "googleuser@example.com",
			EmailVerified: true,
			Name:          "Google User",
		},
	}
	reg.Register(mockGoogle)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, nil)

	// 1. Test Get Authorize URL
	reqAuth := httptest.NewRequest("GET", "/auth/oauth/google/authorize", nil)
	recAuth := httptest.NewRecorder()
	r.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 on oauth authorize, got %d", recAuth.Code)
	}

	var authResp map[string]any
	_ = json.NewDecoder(recAuth.Body).Decode(&authResp)
	if authResp["auth_url"] == "" || authResp["state"] == "" {
		t.Fatalf("expected auth_url and state, got: %+v", authResp)
	}

	// 2. Test Callback Login/Link
	callbackBody := map[string]string{
		"code": "valid-oauth-code",
	}
	bodyBytes, _ := json.Marshal(callbackBody)
	reqCb := httptest.NewRequest("POST", "/auth/oauth/google/callback", bytes.NewReader(bodyBytes))
	reqCb.Header.Set("Content-Type", "application/json")
	recCb := httptest.NewRecorder()
	r.ServeHTTP(recCb, reqCb)

	if recCb.Code != http.StatusOK {
		t.Fatalf("expected 200 on oauth callback, got %d: %s", recCb.Code, recCb.Body.String())
	}

	var tokenResp map[string]any
	_ = json.NewDecoder(recCb.Body).Decode(&tokenResp)
	if tokenResp["access_token"] == "" || tokenResp["refresh_token"] == "" {
		t.Fatalf("expected access and refresh tokens, got: %+v", tokenResp)
	}
}

func TestIntegration_MFAChallengeAndVerification(t *testing.T) {
	handler, svc, _, _ := setupTestAuthSuite(t)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, nil)

	// 1. Create a user
	user, err := svc.Register(context.Background(), "MFA User", "mfauser@example.com", "Password123!")
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// 2. Setup MFA
	setupData, err := svc.SetupMFA(context.Background(), user.ID, "TestApp")
	if err != nil {
		t.Fatalf("failed to setup mfa: %v", err)
	}

	// 3. Verify and Enable MFA with valid code
	totpSvc := mfa.NewMFAService()
	validCode, _ := totpSvc.GenerateCode(setupData.Secret, time.Now())
	err = svc.VerifyAndEnableMFA(context.Background(), user.ID, validCode)
	if err != nil {
		t.Fatalf("failed to enable mfa: %v", err)
	}

	// 4. Try Login -> should return MFA_CHALLENGE_REQUIRED with mfa_token
	loginBody := map[string]string{
		"email":    "mfauser@example.com",
		"password": "Password123!",
	}
	loginBytes, _ := json.Marshal(loginBody)
	reqLogin := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(loginBytes))
	reqLogin.Header.Set("Content-Type", "application/json")
	recLogin := httptest.NewRecorder()
	r.ServeHTTP(recLogin, reqLogin)

	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 on login with mfa challenge, got %d: %s", recLogin.Code, recLogin.Body.String())
	}

	var mfaChallengeResp map[string]any
	_ = json.NewDecoder(recLogin.Body).Decode(&mfaChallengeResp)
	if mfaChallengeResp["mfa_required"] != true || mfaChallengeResp["mfa_token"] == "" {
		t.Fatalf("expected mfa_required=true and mfa_token, got: %+v", mfaChallengeResp)
	}

	mfaToken := mfaChallengeResp["mfa_token"].(string)

	// 5. Complete challenge with TOTP code
	newTotpCode, _ := totpSvc.GenerateCode(setupData.Secret, time.Now())
	challengeBody := map[string]string{
		"mfa_token": mfaToken,
		"code":      newTotpCode,
	}
	challengeBytes, _ := json.Marshal(challengeBody)
	reqChallenge := httptest.NewRequest("POST", "/auth/mfa/challenge", bytes.NewReader(challengeBytes))
	reqChallenge.Header.Set("Content-Type", "application/json")
	recChallenge := httptest.NewRecorder()
	r.ServeHTTP(recChallenge, reqChallenge)

	if recChallenge.Code != http.StatusOK {
		t.Fatalf("expected 200 on challenge complete, got %d: %s", recChallenge.Code, recChallenge.Body.String())
	}

	var fullTokens map[string]any
	_ = json.NewDecoder(recChallenge.Body).Decode(&fullTokens)
	if fullTokens["access_token"] == "" || fullTokens["refresh_token"] == "" {
		t.Fatalf("expected full tokens, got: %+v", fullTokens)
	}

	// 6. Test login challenge using backup recovery code
	reqLogin2 := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(loginBytes))
	recLogin2 := httptest.NewRecorder()
	r.ServeHTTP(recLogin2, reqLogin2)
	var mfaChallengeResp2 map[string]any
	_ = json.NewDecoder(recLogin2.Body).Decode(&mfaChallengeResp2)
	mfaToken2 := mfaChallengeResp2["mfa_token"].(string)

	backupCode := setupData.RecoveryCodes[0]
	recoveryBody := map[string]string{
		"mfa_token": mfaToken2,
		"code":      backupCode,
	}
	recoveryBytes, _ := json.Marshal(recoveryBody)
	reqRecovery := httptest.NewRequest("POST", "/auth/mfa/challenge", bytes.NewReader(recoveryBytes))
	recRecovery := httptest.NewRecorder()
	r.ServeHTTP(recRecovery, reqRecovery)

	if recRecovery.Code != http.StatusOK {
		t.Fatalf("expected 200 using recovery code, got %d: %s", recRecovery.Code, recRecovery.Body.String())
	}

	// 7. Reusing same backup code should FAIL
	reqLogin3 := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(loginBytes))
	recLogin3 := httptest.NewRecorder()
	r.ServeHTTP(recLogin3, reqLogin3)
	var mfaChallengeResp3 map[string]any
	_ = json.NewDecoder(recLogin3.Body).Decode(&mfaChallengeResp3)
	mfaToken3 := mfaChallengeResp3["mfa_token"].(string)

	recoveryBody3 := map[string]string{
		"mfa_token": mfaToken3,
		"code":      backupCode, // already used!
	}
	recoveryBytes3, _ := json.Marshal(recoveryBody3)
	reqRecovery3 := httptest.NewRequest("POST", "/auth/mfa/challenge", bytes.NewReader(recoveryBytes3))
	recRecovery3 := httptest.NewRecorder()
	r.ServeHTTP(recRecovery3, reqRecovery3)

	if recRecovery3.Code == http.StatusOK {
		t.Fatal("expected failure on re-using single-use recovery code")
	}
}

func TestIntegration_SAMLMetadataAndACS(t *testing.T) {
	handler, _, _, _ := setupTestAuthSuite(t)

	r := chi.NewRouter()
	handler.RegisterRoutes(r, nil)

	// 1. Test SAML Metadata endpoint
	reqMeta := httptest.NewRequest("GET", "/auth/sso/saml/metadata", nil)
	recMeta := httptest.NewRecorder()
	r.ServeHTTP(recMeta, reqMeta)

	if recMeta.Code != http.StatusOK {
		t.Fatalf("expected 200 on saml metadata, got %d", recMeta.Code)
	}
	if recMeta.Header().Get("Content-Type") != "application/xml; charset=utf-8" {
		t.Fatalf("expected XML content type, got: %s", recMeta.Header().Get("Content-Type"))
	}

	// 2. Test SAML ACS endpoint
	samlXML := `
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://example.com/acs">
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Subject><NameID>samluser@corporate.com</NameID></Subject>
    <AttributeStatement>
      <Attribute Name="displayName"><AttributeValue>Sammy SSO</AttributeValue></Attribute>
    </AttributeStatement>
  </Assertion>
</Response>`

	b64Response := base64.StdEncoding.EncodeToString([]byte(samlXML))
	acsBody := map[string]string{"saml_response": b64Response}
	acsBytes, _ := json.Marshal(acsBody)

	reqACS := httptest.NewRequest("POST", "/auth/sso/saml/acs", bytes.NewReader(acsBytes))
	reqACS.Header.Set("Content-Type", "application/json")
	recACS := httptest.NewRecorder()
	r.ServeHTTP(recACS, reqACS)

	if recACS.Code != http.StatusOK {
		t.Fatalf("expected 200 on saml acs, got %d: %s", recACS.Code, recACS.Body.String())
	}

	var acsResp map[string]any
	_ = json.NewDecoder(recACS.Body).Decode(&acsResp)
	if acsResp["access_token"] == "" || acsResp["refresh_token"] == "" {
		t.Fatalf("expected tokens on successful SAML login, got: %+v", acsResp)
	}
}
