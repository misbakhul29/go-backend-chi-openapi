package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

type DiscordConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	UserInfoURL  string
}

type DiscordProvider struct {
	cfg         *oauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

func NewDiscordProvider(cfg DiscordConfig, client *http.Client) *DiscordProvider {
	if client == nil {
		client = http.DefaultClient
	}
	userInfoURL := cfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://discord.com/api/users/@me"
	}
	return &DiscordProvider{
		cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"identify", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://discord.com/api/oauth2/authorize",
				TokenURL: "https://discord.com/api/oauth2/token",
			},
		},
		userInfoURL: userInfoURL,
		httpClient:  client,
	}
}

func (p *DiscordProvider) Name() string {
	return "discord"
}

func (p *DiscordProvider) GetAuthURL(state string, opts ...AuthOption) (string, error) {
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

func (p *DiscordProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*oauth2.Token, error) {
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

type discordUserInfo struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	GlobalName string `json:"global_name"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Avatar   string `json:"avatar"`
}

func (p *DiscordProvider) FetchUserProfile(ctx context.Context, token *oauth2.Token) (*UserProfile, error) {
	client := p.cfg.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discord user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discord userinfo returned status %d", resp.StatusCode)
	}

	var info discordUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode discord user info: %w", err)
	}

	displayName := info.GlobalName
	if displayName == "" {
		displayName = info.Username
	}

	avatarURL := ""
	if info.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", info.ID, info.Avatar)
	}

	return &UserProfile{
		ProviderID:    p.Name(),
		AccountID:     info.ID,
		Email:         info.Email,
		EmailVerified: info.Verified,
		Name:          displayName,
		AvatarURL:     avatarURL,
	}, nil
}

