package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	UserURL      string
	EmailsURL    string
}

type GitHubProvider struct {
	cfg        *oauth2.Config
	userURL    string
	emailsURL  string
	httpClient *http.Client
}

func NewGitHubProvider(cfg GitHubConfig, client *http.Client) *GitHubProvider {
	if client == nil {
		client = http.DefaultClient
	}
	userURL := cfg.UserURL
	if userURL == "" {
		userURL = "https://api.github.com/user"
	}
	emailsURL := cfg.EmailsURL
	if emailsURL == "" {
		emailsURL = "https://api.github.com/user/emails"
	}
	return &GitHubProvider{
		cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"read:user", "user:email"},
			Endpoint:     github.Endpoint,
		},
		userURL:    userURL,
		emailsURL:  emailsURL,
		httpClient: client,
	}
}

func (p *GitHubProvider) Name() string {
	return "github"
}

func (p *GitHubProvider) GetAuthURL(state string, opts ...AuthOption) (string, error) {
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

func (p *GitHubProvider) Exchange(ctx context.Context, code string, opts ...ExchangeOption) (*oauth2.Token, error) {
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

type gitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type gitHubEmail struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

func (p *GitHubProvider) FetchUserProfile(ctx context.Context, token *oauth2.Token) (*UserProfile, error) {
	client := p.cfg.Client(ctx, token)
	resp, err := client.Get(p.userURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch github user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github user endpoint returned status %d", resp.StatusCode)
	}

	var user gitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode github user: %w", err)
	}

	displayName := user.Name
	if displayName == "" {
		displayName = user.Login
	}

	email := user.Email
	verified := email != ""

	// If email is private or empty, query /user/emails endpoint
	if email == "" {
		emailsResp, err := client.Get(p.emailsURL)
		if err == nil && emailsResp.StatusCode == http.StatusOK {
			defer emailsResp.Body.Close()
			var emails []gitHubEmail
			if err := json.NewDecoder(emailsResp.Body).Decode(&emails); err == nil {
				for _, e := range emails {
					if e.Primary {
						email = e.Email
						verified = e.Verified
						break
					}
				}
				if email == "" && len(emails) > 0 {
					email = emails[0].Email
					verified = emails[0].Verified
				}
			}
		}
	}

	return &UserProfile{
		ProviderID:    p.Name(),
		AccountID:     strconv.FormatInt(user.ID, 10),
		Email:         email,
		EmailVerified: verified,
		Name:          displayName,
		AvatarURL:     user.AvatarURL,
	}, nil
}
