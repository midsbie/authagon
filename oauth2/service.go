package oauth2

import (
	"fmt"
	"net/http"
)

const (
	ProviderPlaceholder         = "{provider}"
	DefaultCallbackPathTemplate = "/u/auth/" + ProviderPlaceholder + "/callback"
)

type Authenticator interface {
	Begin(w http.ResponseWriter, r *http.Request, config AuthConfig) error
	Finish(w http.ResponseWriter, r *http.Request) (*AuthResult, error)
}

type ServiceConfig struct {
	BaseURL              string // Base URL for the service
	CallbackPathTemplate string // Universal callback path
	Session              AuthSession
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

func (s *OAuth2Service) GetProvider(name string) (Provider, error) {
	if name == "" {
		return nil, ErrNoProvider
	} else if prov, ok := s.providers[name]; !ok {
		return nil, fmt.Errorf("invalid provider name specified: %s", name)
	} else {
		return prov, nil
	}
}

func (s *OAuth2Service) Authenticator(name string) (Authenticator, error) {
	provider, err := s.GetProvider(name)
	if err != nil {
		return nil, err
	}

	return &authenticator{
		svcConf: &s.config, session: s.config.Session, provider: provider}, nil
}
