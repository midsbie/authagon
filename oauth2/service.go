package oauth2

import (
	"fmt"
	"net/http"
)

const (
	ProviderPlaceholder         = "{provider}"
	DefaultCallbackPathTemplate = "/u/auth/" + ProviderPlaceholder + "/callback"
)

type SessionManager interface {
	Set(w http.ResponseWriter, r *http.Request, config AuthConfig) (AuthState, error)
	Get(r *http.Request) (AuthState, error)
	Del(w http.ResponseWriter) error
}

type Authenticator interface {
	Start(w http.ResponseWriter, r *http.Request, config AuthConfig) error
	Complete(w http.ResponseWriter, r *http.Request) (*AuthResult, error)
}

type ServiceConfig struct {
	BaseURL              string // Base URL for the service
	CallbackPathTemplate string // Universal callback path
	SessionManager       SessionManager
}

type providers map[string]Provider

type OAuth2Service struct {
	config    ServiceConfig
	providers providers
}

func NewService(config ServiceConfig) OAuth2Service {
	if config.CallbackPathTemplate == "" {
		config.CallbackPathTemplate = DefaultCallbackPathTemplate
	}

	return OAuth2Service{
		config:    config,
		providers: map[string]Provider{}}
}

func (s *OAuth2Service) Register(provider Provider) {
	s.providers[provider.Name()] = provider
}

func (s *OAuth2Service) Provider(name string) (Provider, error) {
	if name == "" {
		return nil, ErrNoProvider
	} else if prov, ok := s.providers[name]; !ok {
		return nil, fmt.Errorf("invalid provider name specified: %s", name)
	} else {
		return prov, nil
	}
}

func (s *OAuth2Service) NewAuthenticator(name string) (Authenticator, error) {
	provider, err := s.Provider(name)
	if err != nil {
		return nil, err
	}

	return &authenticator{
		svcConf: &s.config, session: s.config.SessionManager, provider: provider}, nil
}
