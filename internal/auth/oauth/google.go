package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	UserInfoURL  string
}

type GoogleProvider struct {
	cfg         *oauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

func NewGoogleProvider(cfg GoogleConfig, client *http.Client) *GoogleProvider {
	if client == nil {
		client = http.DefaultClient
	}
	userInfoURL := cfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	}
	return &GoogleProvider{
		cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
		userInfoURL: userInfoURL,
		httpClient:  client,
	}
}

func (p *GoogleProvider) Name() string {
	return "google"
}

func (p *GoogleProvider) GetAuthURL(state string, opts ...AuthOption) (string, error) {
	params := make(map[string]string)
	for _, opt := range opts {
		opt(params)
	}
	var authOpts []oauth2.AuthCodeOption
	for k, v := range params {
		authOpts = append(authOpts, oauth2.SetAuthURLParam(k, v))
	}
	return p.cfg.AuthCodeURL(state, authOpts...), nil
}

func (p *GoogleProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	params := make(map[string]string)
	for _, opt := range opts {
		opt(params)
	}
	var exchangeOpts []oauth2.AuthCodeOption
	for k, v := range params {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam(k, v))
	}
	return p.cfg.Exchange(ctx, code, exchangeOpts...)
}

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Picture       string `json:"picture"`
}

func (p *GoogleProvider) FetchUserProfile(ctx context.Context, token *oauth2.Token) (*UserProfile, error) {
	client := p.cfg.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch google user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo returned status %d", resp.StatusCode)
	}

	var info googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode google user info: %w", err)
	}

	return &UserProfile{
		ProviderID:    p.Name(),
		AccountID:     info.Sub,
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		Name:          info.Name,
		AvatarURL:     info.Picture,
	}, nil
}

