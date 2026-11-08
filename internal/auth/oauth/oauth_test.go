package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func TestOAuthRegistry(t *testing.T) {
	reg := NewRegistry()
	google := NewGoogleProvider(GoogleConfig{ClientID: "id", ClientSecret: "secret"}, nil)
	reg.Register(google)

	p, err := reg.Get("google")
	if err != nil || p.Name() != "google" {
		t.Fatalf("expected google provider, got err: %v", err)
	}

	_, err = reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent provider")
	}

	list := reg.List()
	if len(list) != 1 || list[0] != "google" {
		t.Fatalf("unexpected provider list: %v", list)
	}
}

func TestGoogleProvider_FetchUserProfile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":            "g-12345",
			"name":           "Jane Doe",
			"email":          "jane@example.com",
			"email_verified": true,
			"picture":        "https://example.com/avatar.jpg",
		})
	}))
	defer ts.Close()

	p := NewGoogleProvider(GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		UserInfoURL:  ts.URL,
	}, ts.Client())

	tok := &oauth2.Token{AccessToken: "fake-access-token"}
	profile, err := p.FetchUserProfile(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if profile.AccountID != "g-12345" || profile.Email != "jane@example.com" || !profile.EmailVerified {
		t.Fatalf("unexpected profile values: %+v", profile)
	}
}

func TestGitHubProvider_FetchUserProfileWithPrivateEmail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         9988,
			"login":      "octocat",
			"name":       "Monalisa Octocat",
			"email":      "", // Private email
			"avatar_url": "https://github.com/images/error/octocat_happy.gif",
		})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"email":    "octo-secondary@example.com",
				"primary":  false,
				"verified": true,
			},
			{
				"email":    "octocat@github.com",
				"primary":  true,
				"verified": true,
			},
		})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	p := NewGitHubProvider(GitHubConfig{
		ClientID:     "gh-id",
		ClientSecret: "gh-secret",
		UserURL:      ts.URL + "/user",
		EmailsURL:    ts.URL + "/user/emails",
	}, ts.Client())

	tok := &oauth2.Token{AccessToken: "fake-gh-token"}
	profile, err := p.FetchUserProfile(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if profile.AccountID != "9988" || profile.Email != "octocat@github.com" || !profile.EmailVerified {
		t.Fatalf("unexpected github profile values: %+v", profile)
	}
}

func TestDiscordProvider_FetchUserProfile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "11223344",
			"username":    "discord_user",
			"global_name": "Discord Gamer",
			"email":       "gamer@discord.gg",
			"verified":    true,
			"avatar":      "abcdef123456",
		})
	}))
	defer ts.Close()

	p := NewDiscordProvider(DiscordConfig{
		ClientID:     "d-id",
		ClientSecret: "d-secret",
		UserInfoURL:  ts.URL,
	}, ts.Client())

	tok := &oauth2.Token{AccessToken: "fake-discord-token"}
	profile, err := p.FetchUserProfile(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if profile.AccountID != "11223344" || profile.Email != "gamer@discord.gg" || profile.Name != "Discord Gamer" {
		t.Fatalf("unexpected discord profile values: %+v", profile)
	}
}

func TestTwitterProvider_FetchUserProfile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":                "22334455",
				"name":              "Twitter Dev",
				"username":          "twitterdev",
				"profile_image_url": "https://pbs.twimg.com/profile_images/pic.jpg",
			},
		})
	}))
	defer ts.Close()

	p := NewTwitterProvider(TwitterConfig{
		ClientID:     "tw-id",
		ClientSecret: "tw-secret",
		UserInfoURL:  ts.URL,
	}, ts.Client())

	tok := &oauth2.Token{AccessToken: "fake-twitter-token"}
	profile, err := p.FetchUserProfile(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if profile.AccountID != "22334455" || profile.Name != "Twitter Dev" {
		t.Fatalf("unexpected twitter profile: %+v", profile)
	}
}

func TestAppleProvider_GenerateClientSecretAndFetch(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal pkcs8: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	apple, err := NewAppleProvider(AppleConfig{
		ClientID:    "com.example.service",
		TeamID:      "TEAM123456",
		KeyID:       "KEY1234567",
		PrivateKey:  string(pemBlock),
		RedirectURL: "https://example.com/callback",
	}, nil)
	if err != nil {
		t.Fatalf("failed to create apple provider: %v", err)
	}

	secret, err := apple.GenerateClientSecret(time.Hour)
	if err != nil || secret == "" {
		t.Fatalf("failed to generate client secret: %v", err)
	}

	// Create a dummy signed id_token
	claims := jwt.MapClaims{
		"sub":            "apple-user-001",
		"email":          "appleuser@icloud.com",
		"email_verified": true,
	}
	idToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signedIDToken, err := idToken.SignedString(privKey)
	if err != nil {
		t.Fatalf("failed to sign id token: %v", err)
	}

	tok := (&oauth2.Token{AccessToken: "fake-access"}).WithExtra(map[string]any{
		"id_token": signedIDToken,
	})

	profile, err := apple.FetchUserProfile(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if profile.AccountID != "apple-user-001" || profile.Email != "appleuser@icloud.com" || !profile.EmailVerified {
		t.Fatalf("unexpected profile values: %+v", profile)
	}
}

