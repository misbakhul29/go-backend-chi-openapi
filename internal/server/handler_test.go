package handler_test

import (
	"testing"

	"github.com/misbakhul29/backend-framework/config"
	handler "github.com/misbakhul29/backend-framework/internal/server"
)

func TestNewServer_Initialization(t *testing.T) {
	cfg := &config.Env{
		JWT: config.JWT{
			Secret:     "test-secret",
			AccessTTL:  900,
			RefreshTTL: 604800,
		},
		OAuth: config.OAuth{
			Google: config.OAuthProvider{
				ClientID:     "google-id",
				ClientSecret: "google-secret",
				RedirectURL:  "https://example.com/oauth/google",
			},
		},
		SAML: config.SAML{
			EntityID: "https://example.com/saml/metadata",
			ACSURL:   "https://example.com/saml/acs",
		},
	}

	srv := handler.NewServer(nil, nil, nil, cfg)
	if srv == nil {
		t.Fatal("expected NewServer to return non-nil Server")
	}
	if srv.AuthHandler == nil {
		t.Error("expected AuthHandler to be initialized")
	}
	if srv.HealthHandler == nil {
		t.Error("expected HealthHandler to be initialized")
	}
}

func TestNewServer_NilConfig(t *testing.T) {
	srv := handler.NewServer(nil, nil, nil, nil)
	if srv == nil {
		t.Fatal("expected NewServer with nil config to return non-nil Server")
	}
}

