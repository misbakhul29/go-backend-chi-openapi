package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func TestOIDCProvider_DiscoveryAndVerify(t *testing.T) {
	// Generate local RSA key for JWKS testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	nB64 := base64.RawURLEncoding.EncodeToString(privKey.N.Bytes())
	eBytes := []byte{1, 0, 1} // 65537
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	kid := "test-kid-1"
	var ts *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 ts.URL,
			"authorization_endpoint": ts.URL + "/authorize",
			"token_endpoint":         ts.URL + "/token",
			"jwks_uri":               ts.URL + "/jwks.json",
			"userinfo_endpoint":      ts.URL + "/userinfo",
		})
	})

	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": kid,
					"use": "sig",
					"n":   nB64,
					"e":   eB64,
				},
			},
		})
	})

	ts = httptest.NewServer(mux)
	defer ts.Close()

	provider, err := NewOIDCProvider(context.Background(), OIDCConfig{
		IssuerURL:    ts.URL,
		ClientID:     "sso-client-id",
		ClientSecret: "sso-secret",
		RedirectURL:  "https://app.example.com/callback",
	}, ts.Client())
	if err != nil {
		t.Fatalf("failed to create oidc provider: %v", err)
	}

	// Forge signed ID Token with private RSA key
	claims := jwt.MapClaims{
		"iss":            ts.URL,
		"sub":            "corp-user-7788",
		"aud":            "sso-client-id",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"email":          "alice@enterprise.org",
		"email_verified": true,
		"name":           "Alice Enterprise",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedIDToken, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign id_token: %v", err)
	}

	tok := (&oauth2.Token{AccessToken: "at"}).WithExtra(map[string]any{
		"id_token": signedIDToken,
	})

	profile, err := provider.FetchUserProfile(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error fetching profile: %v", err)
	}

	if profile.AccountID != "corp-user-7788" || profile.Email != "alice@enterprise.org" || !profile.EmailVerified {
		t.Fatalf("unexpected oidc profile: %+v", profile)
	}
}

func TestSAMLService_SPMetadataAndAuthnRequest(t *testing.T) {
	service, err := NewSAMLService(SAMLSPConfig{
		EntityID:    "https://backend.example.com/saml/metadata",
		ACSURL:      "https://backend.example.com/saml/acs",
		IdPEntityID: "https://idp.okta.com/exk12345",
		IdPSSOURL:   "https://idp.okta.com/app/sso",
	})
	if err != nil {
		t.Fatalf("failed to create saml service: %v", err)
	}

	metadata, err := service.GenerateSPMetadata()
	if err != nil || len(metadata) == 0 {
		t.Fatalf("failed to generate metadata: %v", err)
	}

	authnURL, err := service.GenerateAuthnRequestURL("https://frontend.example.com/dashboard")
	if err != nil || authnURL == "" {
		t.Fatalf("failed to generate authn request url: %v", err)
	}
}

func TestSAMLService_ProcessACS(t *testing.T) {
	service, err := NewSAMLService(SAMLSPConfig{
		EntityID: "https://backend.example.com/saml/metadata",
		ACSURL:   "https://backend.example.com/saml/acs",
	})
	if err != nil {
		t.Fatalf("failed to create saml service: %v", err)
	}

	samlXML := `
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://backend.example.com/saml/acs">
  <Status>
    <StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Subject>
      <NameID>samluser@corporate.com</NameID>
    </Subject>
    <AttributeStatement>
      <Attribute Name="displayName">
        <AttributeValue>Sam L. User</AttributeValue>
      </Attribute>
    </AttributeStatement>
  </Assertion>
</Response>`

	b64Response := base64.StdEncoding.EncodeToString([]byte(samlXML))
	profile, err := service.ProcessACS(b64Response)
	if err != nil {
		t.Fatalf("unexpected error processing ACS: %v", err)
	}

	if profile.Email != "samluser@corporate.com" || profile.Name != "Sam L. User" || profile.ProviderID != "saml" {
		t.Fatalf("unexpected saml profile result: %+v", profile)
	}
}
