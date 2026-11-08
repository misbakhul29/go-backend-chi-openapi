package sso

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/misbakhul29/backend-framework/internal/auth/oauth"
)

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type oidcDiscovery struct {
	Issuer        string `json:"issuer"`
	AuthURL       string `json:"authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
	UserinfoURL   string `json:"userinfo_endpoint"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type OIDCProvider struct {
	cfg         OIDCConfig
	oauthCfg    *oauth2.Config
	jwksURI     string
	userinfoURL string
	httpClient  *http.Client

	mu        sync.RWMutex
	keysCache map[string]*rsa.PublicKey
	keysExp   time.Time
}

func NewOIDCProvider(ctx context.Context, cfg OIDCConfig, client *http.Client) (*OIDCProvider, error) {
	if client == nil {
		client = http.DefaultClient
	}

	discoURL := strings.TrimSuffix(cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch oidc discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery returned status: %d", resp.StatusCode)
	}

	var disco oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil {
		return nil, fmt.Errorf("failed to decode oidc discovery: %w", err)
	}

	return &OIDCProvider{
		cfg: cfg,
		oauthCfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  disco.AuthURL,
				TokenURL: disco.TokenURL,
			},
		},
		jwksURI:     disco.JWKSURI,
		userinfoURL: disco.UserinfoURL,
		httpClient:  client,
		keysCache:   make(map[string]*rsa.PublicKey),
	}, nil
}

func (p *OIDCProvider) Name() string {
	return "oidc"
}

func (p *OIDCProvider) GetAuthURL(state string, opts ...oauth.AuthOption) (string, error) {
	params := make(map[string]string)
	for _, opt := range opts {
		opt(params)
	}
	var authOpts []oauth2.AuthCodeOption
	for k, v := range params {
		authOpts = append(authOpts, oauth2.SetAuthURLParam(k, v))
	}
	return p.oauthCfg.AuthCodeURL(state, authOpts...), nil
}

func (p *OIDCProvider) Exchange(ctx context.Context, code string, opts ...oauth.ExchangeOption) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	params := make(map[string]string)
	for _, opt := range opts {
		opt(params)
	}
	var exchangeOpts []oauth2.AuthCodeOption
	for k, v := range params {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam(k, v))
	}
	return p.oauthCfg.Exchange(ctx, code, exchangeOpts...)
}

func (p *OIDCProvider) fetchJWKS(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if time.Now().Before(p.keysExp) && len(p.keysCache) > 0 {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURI, nil)
	if err != nil {
		return err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned status: %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	newCache := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		var eInt int
		for _, b := range eBytes {
			eInt = (eInt << 8) | int(b)
		}

		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}
		newCache[k.Kid] = pubKey
	}

	p.keysCache = newCache
	p.keysExp = time.Now().Add(1 * time.Hour)
	return nil
}

func (p *OIDCProvider) VerifyIDToken(ctx context.Context, rawIDToken string) (*oauth.UserProfile, error) {
	if err := p.fetchJWKS(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %w", err)
	}

	parsedToken, err := jwt.Parse(rawIDToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid in token header")
		}

		p.mu.RLock()
		pubKey, ok := p.keysCache[kid]
		p.mu.RUnlock()

		if !ok {
			return nil, fmt.Errorf("public key not found for kid: %s", kid)
		}
		return pubKey, nil
	}, jwt.WithIssuer(p.cfg.IssuerURL), jwt.WithAudience(p.cfg.ClientID))

	if err != nil {
		return nil, fmt.Errorf("invalid oidc id_token: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return nil, errors.New("invalid token claims")
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)

	var emailVerified bool
	switch v := claims["email_verified"].(type) {
	case bool:
		emailVerified = v
	case string:
		emailVerified = strings.ToLower(v) == "true"
	}

	return &oauth.UserProfile{
		ProviderID:    p.Name(),
		AccountID:     sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		AvatarURL:     picture,
	}, nil
}

func (p *OIDCProvider) FetchUserProfile(ctx context.Context, token *oauth2.Token) (*oauth.UserProfile, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if ok && rawIDToken != "" {
		profile, err := p.VerifyIDToken(ctx, rawIDToken)
		if err == nil && profile.Email != "" {
			return profile, nil
		}
	}

	// Fallback to userinfo endpoint if id_token not present or incomplete
	if p.userinfoURL != "" {
		client := p.oauthCfg.Client(ctx, token)
		resp, err := client.Get(p.userinfoURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var claims map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&claims); err == nil {
				sub, _ := claims["sub"].(string)
				email, _ := claims["email"].(string)
				name, _ := claims["name"].(string)
				return &oauth.UserProfile{
					ProviderID:    p.Name(),
					AccountID:     sub,
					Email:         email,
					EmailVerified: email != "",
					Name:          name,
				}, nil
			}
		}
	}

	return nil, errors.New("unable to retrieve user profile from oidc provider")
}
