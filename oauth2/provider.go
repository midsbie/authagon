package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type MapProfileFn func(ParsedProfile, []byte) (Profile, error)

type Provider interface {
	Name() string
	ApplyServiceConfig(config ServiceConfig)
	Begin(w http.ResponseWriter, r *http.Request, config AuthConfig) error
	Finish(w http.ResponseWriter, r *http.Request) (*AuthResult, error)
}

type AuthSession interface {
	Set(w http.ResponseWriter, r *http.Request, config AuthConfig) (AuthState, error)
	Get(r *http.Request) (AuthState, error)
	Del(w http.ResponseWriter) error
}

type AuthResult struct {
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

type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	Issuer       string
	CallbackURL  string
}

type endpoint struct {
	oauth2.Endpoint
	ProfileURL string
}

type ProviderBlueprint struct {
	name       string
	endpoint   endpoint
	scopes     []string
	mapProfile MapProfileFn
}

func (b *ProviderBlueprint) Configure(options ProviderConfig) *StandardProvider {
	return &StandardProvider{*b, options, nil}
}

type StandardProvider struct {
	provider ProviderBlueprint
	config   ProviderConfig
	session  AuthSession
}

func (p *StandardProvider) Name() string {
	return p.provider.name
}

func (p *StandardProvider) ApplyServiceConfig(config ServiceConfig) {
	p.session = config.Session
	cbp := strings.Replace(
		config.CallbackPathTemplate, providerPlaceholder, p.provider.name, -1)
	p.config.CallbackURL = strings.TrimSuffix(config.BaseURL, "/") +
		"/" + strings.Trim(cbp, "/")
}

func (p *StandardProvider) Begin(w http.ResponseWriter, r *http.Request, config AuthConfig) error {
	auth, err := p.session.Set(w, r, config)
	if err != nil {
		return err
	}

	conf := p.configure()
	loginURL := conf.AuthCodeURL(auth.State)
	http.Redirect(w, r, loginURL, http.StatusFound)
	return nil
}

func (p *StandardProvider) Finish(w http.ResponseWriter, r *http.Request) (*AuthResult, error) {
	receivedState := r.URL.Query().Get("state")
	if receivedState == "" {
		return nil, fmt.Errorf("state missing")
	}

	session, err := p.session.Get(r)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	} else if session.State != receivedState {
		return nil, fmt.Errorf("unexpected state")
	} else if err = p.session.Del(w); err != nil {
		log.Printf("failed to delete auth session: %s", err.Error())
	}

	conf := p.configure()
	token, err := conf.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		return nil, fmt.Errorf("exchange failed: %w", err)
	}

	client := conf.Client(context.Background(), token)
	preq, err := client.Get(p.provider.endpoint.ProfileURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile")
	}

	defer func() {
		if e := preq.Body.Close(); e != nil {
			log.Printf("failed to close response body: %s", e.Error())
		}
	}()

	byteProfile, err := io.ReadAll(preq.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile")
	}

	mappedProfile := map[string]interface{}{}
	if err := json.Unmarshal(byteProfile, &mappedProfile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profile: %w", err)
	}

	profile, err := p.provider.mapProfile(mappedProfile, byteProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to map profile: %w", err)
	}

	return &AuthResult{
		Profile:     profile,
		Token:       *token,
		RedirectURL: session.RedirectURL}, nil
}

func (p *StandardProvider) configure() oauth2.Config {
	return oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     p.provider.endpoint.Endpoint,
		Scopes:       p.provider.scopes,
		RedirectURL:  p.config.CallbackURL,
	}
}
