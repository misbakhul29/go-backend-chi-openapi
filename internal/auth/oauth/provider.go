package oauth

import (
	"context"

	"golang.org/x/oauth2"
)

type UserProfile struct {
	ProviderID    string
	AccountID     string
	Email         string
	EmailVerified bool
	Name          string
	AvatarURL     string
}

type AuthOption func(map[string]string)

func WithCodeChallenge(challenge string) AuthOption {
	return func(params map[string]string) {
		params["code_challenge"] = challenge
		params["code_challenge_method"] = "S256"
	}
}

type ExchangeOption func(map[string]string)

func WithCodeVerifier(verifier string) ExchangeOption {
	return func(params map[string]string) {
		params["code_verifier"] = verifier
	}
}

type OAuthProvider interface {
	Name() string
	GetAuthURL(state string, opts ...AuthOption) (string, error)
	Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*oauth2.Token, error)
	FetchUserProfile(ctx context.Context, token *oauth2.Token) (*UserProfile, error)
}

