package oauth2

import (
	"strings"

	"golang.org/x/oauth2"
)

// ProviderID identifies a logical OAuth2/OIDC provider (e.g. "google",
// "microsoft"). It is used as the key for registration and lookup in
// OAuth2Service.
type ProviderID string

// ProfileExtractor converts provider-specific user info data into a
// portable Profile representation.
type ProfileExtractor func(ProfileMap, []byte) (Profile, error)

// ProviderEndpoints describes the OAuth2 endpoints and user info URL
// for a provider.
type ProviderEndpoints struct {
	OAuth2     oauth2.Endpoint
	ProfileURL string
}

// ProviderSpec captures the protocol-level definition of an OAuth2/OIDC
// provider: its stable ID, endpoints, default scopes, and how to map
// user info into a Profile. It has no environment-specific details such
// as client IDs or callback URLs.
type ProviderSpec struct {
	ID             ProviderID
	Endpoints      ProviderEndpoints
	DefaultScopes  []string
	ExtractProfile ProfileExtractor
}

// ProviderConfig carries environment-specific configuration for a
// provider instance: client credentials, optional scope overrides, and
// an optional explicit callback URL.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	CallbackURL  string
}

// ProviderOption customises a ProviderConfig when constructing a
// Provider from a ProviderSpec.
type ProviderOption func(*ProviderConfig)

// WithScopes overrides the default scopes for a provider instance.
func WithScopes(scopes ...string) ProviderOption {
	return func(c *ProviderConfig) {
		c.Scopes = append([]string(nil), scopes...)
	}
}

// WithCallbackURL overrides the callback URL for a provider instance.
// When not set, the callback URL is derived from ServiceConfig.
func WithCallbackURL(callbackURL string) ProviderOption {
	return func(c *ProviderConfig) {
		c.CallbackURL = callbackURL
	}
}

// Provider represents an OAuth2/OIDC identity provider bound to a
// specific environment (client credentials, optional callback URL). It
// exposes enough information for OAuth2Service and Authenticator to
// drive the protocol and extract a Profile.
type Provider interface {
	ID() ProviderID
	Config(*serviceConfig) oauth2.Config
	ProfileURL() string
	ExtractProfile(ProfileMap, []byte) (Profile, error)
}

// standardProvider is the default implementation of Provider built from
// a ProviderSpec and ProviderConfig.
type standardProvider struct {
	spec   ProviderSpec
	config ProviderConfig
}

// NewProvider constructs a Provider from the given spec and config,
// applying any options. It panics if the resulting configuration is
// obviously invalid (e.g. missing client ID/secret); applications
// should catch such issues at startup.
func NewProvider(spec ProviderSpec, cfg ProviderConfig, opts ...ProviderOption) Provider {
	for _, opt := range opts {
		opt(&cfg)
	}

	// Shallow validation; more nuanced checks can be added later.
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		panic("oauth2: ProviderConfig requires ClientID and ClientSecret")
	}

	return &standardProvider{
		spec:   spec,
		config: cfg,
	}
}

// NewCustomProvider constructs a Provider from the given components
// without requiring an explicit ProviderSpec value at the call site. It
// is a thin convenience wrapper around NewProvider.
func NewCustomProvider(
	id ProviderID,
	endpoints ProviderEndpoints,
	defaultScopes []string,
	extractor ProfileExtractor,
	cfg ProviderConfig,
	opts ...ProviderOption,
) Provider {
	spec := ProviderSpec{
		ID:             id,
		Endpoints:      endpoints,
		DefaultScopes:  append([]string(nil), defaultScopes...),
		ExtractProfile: extractor,
	}
	return NewProvider(spec, cfg, opts...)
}

func (p *standardProvider) ID() ProviderID { return p.spec.ID }

func (p *standardProvider) Config(conf *serviceConfig) oauth2.Config {
	callbackURL := p.config.CallbackURL
	if callbackURL == "" {
		cbp := strings.Replace(
			conf.CallbackPathTemplate, ProviderPlaceholder, string(p.spec.ID), -1)
		callbackURL = strings.TrimSuffix(conf.BaseURL, "/") +
			"/" + strings.Trim(cbp, "/")
	}

	scopes := p.config.Scopes
	if len(scopes) == 0 {
		scopes = p.spec.DefaultScopes
	}

	return oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     p.spec.Endpoints.OAuth2,
		Scopes:       scopes,
		RedirectURL:  callbackURL,
	}
}

func (p *standardProvider) ProfileURL() string {
	return p.spec.Endpoints.ProfileURL
}

func (p *standardProvider) ExtractProfile(data ProfileMap, raw []byte) (Profile, error) {
	return p.spec.ExtractProfile(data, raw)
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
