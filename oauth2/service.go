// Package oauth2 provides an OAuth2 client, provider abstractions, handshake state management, and
// an application session controller.  It focuses on clear separation between short-lived handshake
// state and long-lived application sessions.
package oauth2

import (
	"fmt"
	"net/http"
)

const (
	ProviderPlaceholder         = "{provider}"
	DefaultCallbackPathTemplate = "/u/auth/" + ProviderPlaceholder + "/callback"
)

// StateStore manages short-lived OAuth2/OIDC handshake state (state, nonce, redirect URL).
// It is not responsible for long-lived application sessions.
type StateStore interface {
	Set(w http.ResponseWriter, r *http.Request, config AuthConfig) (AuthState, error)
	Get(r *http.Request) (AuthState, error)
	Del(w http.ResponseWriter) error
}

// Authenticator coordinates the OAuth2/OIDC redirect flow for a single provider using a StateStore
// owned by an OAuth2Service. It does not manage long-lived application sessions.
type Authenticator interface {
	Start(w http.ResponseWriter, r *http.Request, config AuthConfig) error
	Complete(w http.ResponseWriter, r *http.Request) (*AuthResult, error)
}

// serviceConfig holds construction-time configuration for OAuth2Service.
type serviceConfig struct {
	BaseURL              string            // Base URL for the service
	CallbackPathTemplate string            // Universal callback path
	StateStore           StateStore        // Handshake state storage
	RedirectValidator    RedirectValidator // Optional redirect validator; defaults to SanitizeRedirectURL
}

// ServiceOption configures an OAuth2Service during construction.
type ServiceOption func(*serviceConfig)

// WithBaseURL sets the BaseURL used when deriving provider callback URLs.
func WithBaseURL(baseURL string) ServiceOption {
	return func(c *serviceConfig) {
		c.BaseURL = baseURL
	}
}

// WithCallbackPathTemplate sets the CallbackPathTemplate used for deriving provider callback URLs.
func WithCallbackPathTemplate(tmpl string) ServiceOption {
	return func(c *serviceConfig) {
		c.CallbackPathTemplate = tmpl
	}
}

// WithRedirectValidator sets a custom RedirectValidator used to normalize and validate post-login
// redirect URLs.
func WithRedirectValidator(v RedirectValidator) ServiceOption {
	return func(c *serviceConfig) {
		c.RedirectValidator = v
	}
}

type providers map[ProviderID]Provider

type OAuth2Service struct {
	config    serviceConfig
	providers providers
}

// NewService constructs an OAuth2Service from the supplied ServiceOptions, using the provided
// StateStore. If no CallbackPathTemplate is provided, the default is used. If no RedirectValidator
// is provided, SanitizeRedirectURL is used. An error is returned if the StateStore is nil.
func NewService(stateStore StateStore, opts ...ServiceOption) (*OAuth2Service, error) {
	cfg := serviceConfig{StateStore: stateStore}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.CallbackPathTemplate == "" {
		cfg.CallbackPathTemplate = DefaultCallbackPathTemplate
	}

	if cfg.RedirectValidator == nil {
		cfg.RedirectValidator = SanitizeRedirectURL
	}

	if cfg.StateStore == nil {
		return nil, fmt.Errorf("oauth2: StateStore must not be nil")
	}

	return &OAuth2Service{
		config:    cfg,
		providers: map[ProviderID]Provider{},
	}, nil
}

// Register adds a Provider to the OAuth2Service under its ID.
// Register at startup, then treat as read-only. Callers should ensure proper synchronization since
// no guarantee is made about concurrent access.
func (s *OAuth2Service) Register(provider Provider) {
	s.providers[provider.ID()] = provider
}

// Provider retrieves a registered Provider by name.
// An error is returned if the name is empty or no such provider is registered.
func (s *OAuth2Service) Provider(name string) (Provider, error) {
	if name == "" {
		return nil, ErrNoProvider
	} else if prov, ok := s.providers[ProviderID(name)]; !ok {
		return nil, fmt.Errorf("invalid provider name specified: %s", name)
	} else {
		return prov, nil
	}
}

// NewAuthenticator constructs an Authenticator for the named provider.
func (s *OAuth2Service) NewAuthenticator(name string) (Authenticator, error) {
	provider, err := s.Provider(name)
	if err != nil {
		return nil, err
	}

	return &authenticator{
		svcConf:  &s.config,
		state:    s.config.StateStore,
		provider: provider,
	}, nil
}
