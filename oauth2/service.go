package oauth2

import (
	"fmt"
)

const (
	providerPlaceholder         = "{provider}"
	defaultCallbackPathTemplate = "/auth/" + providerPlaceholder + "/callback"
)

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
		config.CallbackPathTemplate = defaultCallbackPathTemplate
	}

	return OAuth2Service{
		config:    config,
		providers: map[string]Provider{}}
}

func (s *OAuth2Service) Register(provider Provider) {
	provider.ApplyServiceConfig(s.config)
	s.providers[provider.Name()] = provider
}

func (s *OAuth2Service) GetProvider(name string) (Provider, error) {
	if name == "" {
		return nil, fmt.Errorf("no provider name specified")
	} else if prov, ok := s.providers[name]; !ok {
		return nil, fmt.Errorf("invalid provider name specified: %s", name)
	} else {
		return prov, nil
	}
}
