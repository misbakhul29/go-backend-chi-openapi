package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

type TwitterConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	UserInfoURL  string
}

type TwitterProvider struct {
	cfg         *oauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

func NewTwitterProvider(cfg TwitterConfig, client *http.Client) *TwitterProvider {
	if client == nil {
		client = http.DefaultClient
	}
	userInfoURL := cfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://api.twitter.com/2/users/me?user.fields=profile_image_url,verified"
	}
	return &TwitterProvider{
		cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"tweet.read", "users.read", "offline.access"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://twitter.com/i/oauth2/authorize",
				TokenURL: "https://api.twitter.com/2/oauth2/token",
			},
		},
		userInfoURL: userInfoURL,
		httpClient:  client,
	}
}

func (p *TwitterProvider) Name() string {
	return "twitter"
}

func (p *TwitterProvider) GetAuthURL(state string, opts ...AuthOption) (string, error) {
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

func (p *TwitterProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*oauth2.Token, error) {
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

type twitterUserData struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	ProfileImageURL string `json:"profile_image_url"`
}

type twitterUserInfo struct {
	Data twitterUserData `json:"data"`
}

func (p *TwitterProvider) FetchUserProfile(ctx context.Context, token *oauth2.Token) (*UserProfile, error) {
	client := p.cfg.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch twitter user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("twitter userinfo returned status %d", resp.StatusCode)
	}

	var info twitterUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode twitter user info: %w", err)
	}

	return &UserProfile{
		ProviderID:    p.Name(),
		AccountID:     info.Data.ID,
		Email:         fmt.Sprintf("%s@twitter.local", info.Data.Username),
		EmailVerified: false,
		Name:          info.Data.Name,
		AvatarURL:     info.Data.ProfileImageURL,
	}, nil
}

