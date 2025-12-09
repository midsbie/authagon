package oauth2

import (
	"strings"

	"golang.org/x/oauth2"
)

// Provider represents an OAuth2/OIDC identity provider. Implementations
// are responsible for configuring an oauth2.Config, exposing protocol
// endpoints, and extracting a Profile from the provider-specific user
// info response.
type Provider interface {
	Name() string
	Configure(conf *ServiceConfig) oauth2.Config
	Endpoints() endpoints
	ExtractProfile(data ProfileMap, _ []byte) (Profile, error)
}

// AuthResult is the payload stored in long-lived application sessions.
// It captures which provider authenticated the user, the extracted
// Profile, the issued OAuth2 token, and an optional post-login
// RedirectURL.
type AuthResult struct {
	Provider    string
	Profile     Profile
	Token       oauth2.Token
	RedirectURL string
}

// AuthState is the short-lived handshake state persisted by a
// StateStore during the OAuth2/OIDC redirect flow. It carries CSRF
// protection (State), a Nonce, an optional Audience, and the
// post-login RedirectURL requested by the caller.
type AuthState struct {
	State       string
	Nonce       string
	Audience    string
	RedirectURL string
}

// AuthConfig contains request-scoped configuration for starting a
// handshake. At present it carries the requested post-login
// RedirectURL, which is normalized and validated by the service's
// RedirectValidator before being persisted in AuthState.
type AuthConfig struct {
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
