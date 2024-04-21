package oauth2

import (
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type Provider interface {
	Name() string
	Configure(conf *ServiceConfig) oauth2.Config
	Endpoints() endpoints
	ExtractProfile(data ProfileMap, _ []byte) (Profile, error)
}

type AuthSession interface {
	Set(w http.ResponseWriter, r *http.Request, config AuthConfig) (AuthState, error)
	Get(r *http.Request) (AuthState, error)
	Del(w http.ResponseWriter) error
}

type AuthResult struct {
	Provider    string
	Profile     Profile
	Token       oauth2.Token
	RedirectURL string
}

type AuthState struct {
	State       string
	Nonce       string
	Audience    string
	RedirectURL string
}

type AuthConfig struct {
	Audience    string
	RedirectURL string
}

type StandardProviderOption func(*ProviderConfig)

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	Issuer       string
	CallbackURL  string
}

func WithProviderIssuer(issuer string) StandardProviderOption {
	return func(c *ProviderConfig) {
		c.Issuer = issuer
	}
}

func WithCallbackURL(callbackURL string) StandardProviderOption {
	return func(c *ProviderConfig) {
		c.CallbackURL = callbackURL
	}
}

func NewProviderConfig(clientID string, clientSecret string,
	options []StandardProviderOption) ProviderConfig {
	config := ProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret}

	for _, option := range options {
		option(&config)
	}
	return config
}

type endpoints struct {
	OAuth2     oauth2.Endpoint
	ProfileURL string
}

type StandardProvider struct {
	name      string
	endpoints endpoints
	scopes    []string
	config    ProviderConfig
}

func (p *StandardProvider) Name() string         { return p.name }
func (p *StandardProvider) Endpoints() endpoints { return p.endpoints }

func (p *StandardProvider) Configure(conf *ServiceConfig) oauth2.Config {
	callbackURL := p.config.CallbackURL
	if callbackURL == "" {
		cbp := strings.Replace(
			conf.CallbackPathTemplate, ProviderPlaceholder, p.name, -1)
		callbackURL = strings.TrimSuffix(conf.BaseURL, "/") +
			"/" + strings.Trim(cbp, "/")
	}

	return oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     p.endpoints.OAuth2,
		Scopes:       p.scopes,
		RedirectURL:  callbackURL,
	}
}
