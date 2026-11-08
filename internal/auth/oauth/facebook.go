package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

type FacebookConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	UserInfoURL  string
}

type FacebookProvider struct {
	cfg         *oauth2.Config
	userInfoURL string
	httpClient  *http.Client
}

func NewFacebookProvider(cfg FacebookConfig, client *http.Client) *FacebookProvider {
	if client == nil {
		client = http.DefaultClient
	}
	userInfoURL := cfg.UserInfoURL
	if userInfoURL == "" {
		userInfoURL = "https://graph.facebook.com/me?fields=id,name,email,picture.type(large)"
	}
	return &FacebookProvider{
		cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"email", "public_profile"},
			Endpoint:     facebook.Endpoint,
		},
		userInfoURL: userInfoURL,
		httpClient:  client,
	}
}

func (p *FacebookProvider) Name() string {
	return "facebook"
}

func (p *FacebookProvider) GetAuthURL(state string, opts ...AuthOption) (string, error) {
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

func (p *FacebookProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*oauth2.Token, error) {
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

type fbPictureData struct {
	URL string `json:"url"`
}

type fbPicture struct {
	Data fbPictureData `json:"data"`
}

type facebookUserInfo struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Email   string    `json:"email"`
	Picture fbPicture `json:"picture"`
}

func (p *FacebookProvider) FetchUserProfile(ctx context.Context, token *oauth2.Token) (*UserProfile, error) {
	client := p.cfg.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch facebook user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebook userinfo returned status %d", resp.StatusCode)
	}

	var info facebookUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode facebook user info: %w", err)
	}

	return &UserProfile{
		ProviderID:    p.Name(),
		AccountID:     info.ID,
		Email:         info.Email,
		EmailVerified: info.Email != "",
		Name:          info.Name,
		AvatarURL:     info.Picture.Data.URL,
	}, nil
}
