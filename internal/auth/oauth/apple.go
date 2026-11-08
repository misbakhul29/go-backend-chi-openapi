package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type AppleConfig struct {
	ClientID    string // Service ID (e.g. com.example.service)
	TeamID      string // 10-char Team ID
	KeyID       string // 10-char Key ID
	PrivateKey  string // PEM encoded PKCS#8 private key
	RedirectURL string
}

type AppleProvider struct {
	cfg        *oauth2.Config
	teamID     string
	keyID      string
	privKey    *ecdsa.PrivateKey
	httpClient *http.Client
}

func NewAppleProvider(cfg AppleConfig, client *http.Client) (*AppleProvider, error) {
	if client == nil {
		client = http.DefaultClient
	}

	var privKey *ecdsa.PrivateKey
	if cfg.PrivateKey != "" {
		block, _ := pem.Decode([]byte(cfg.PrivateKey))
		if block == nil {
			return nil, errors.New("failed to decode apple PEM private key")
		}
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse apple PKCS8 private key: %w", err)
		}
		var ok bool
		privKey, ok = parsedKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("apple private key is not an ECDSA key")
		}
	}

	return &AppleProvider{
		cfg: &oauth2.Config{
			ClientID:    cfg.ClientID,
			RedirectURL: cfg.RedirectURL,
			Scopes:      []string{"name", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://appleid.apple.com/auth/authorize",
				TokenURL: "https://appleid.apple.com/auth/token",
			},
		},
		teamID:     cfg.TeamID,
		keyID:      cfg.KeyID,
		privKey:    privKey,
		httpClient: client,
	}, nil
}

func (p *AppleProvider) Name() string {
	return "apple"
}

func (p *AppleProvider) GenerateClientSecret(ttl time.Duration) (string, error) {
	if p.privKey == nil {
		return "", errors.New("apple private key not configured")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": p.teamID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": p.cfg.ClientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = p.keyID

	return token.SignedString(p.privKey)
}

func (p *AppleProvider) GetAuthURL(state string, opts ...AuthOption) (string, error) {
	params := make(map[string]string)
	for _, opt := range opts {
		opt(params)
	}
	var authOpts []oauth2.AuthCodeOption
	for k, v := range params {
		authOpts = append(authOpts, oauth2.SetAuthURLParam(k, v))
	}
	// Apple recommends form_post for Web Sign In
	authOpts = append(authOpts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	return p.cfg.AuthCodeURL(state, authOpts...), nil
}

func (p *AppleProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	secret, err := p.GenerateClientSecret(24 * time.Hour)
	if err != nil {
		// Fallback to configured secret if dynamic key is unavailable (e.g. testing)
		secret = p.cfg.ClientSecret
	}

	cfg := *p.cfg
	cfg.ClientSecret = secret

	params := make(map[string]string)
	for _, opt := range opts {
		opt(params)
	}
	var exchangeOpts []oauth2.AuthCodeOption
	for k, v := range params {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam(k, v))
	}
	return cfg.Exchange(ctx, code, exchangeOpts...)
}

func (p *AppleProvider) FetchUserProfile(ctx context.Context, token *oauth2.Token) (*UserProfile, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("missing id_token in apple token response")
	}

	// Parse unverified claims to extract identity
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(rawIDToken, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse apple id_token: %w", err)
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	var emailVerified bool
	switch v := claims["email_verified"].(type) {
	case bool:
		emailVerified = v
	case string:
		emailVerified = strings.ToLower(v) == "true"
	}

	name := ""
	if email != "" && strings.Contains(email, "@") {
		name = strings.Split(email, "@")[0]
	}

	return &UserProfile{
		ProviderID:    p.Name(),
		AccountID:     sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
	}, nil
}
