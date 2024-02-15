package oauth2

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/midsbie/authagon/secutil"
	"golang.org/x/oauth2"
)

type Provider interface {
	Name() string
	Configure(config ServiceConfig)
	Begin(w http.ResponseWriter, r *http.Request, config AuthConfig) *secutil.HTTPError
	Finish(w http.ResponseWriter, r *http.Request) (*AuthResult, *secutil.HTTPError)
}

type ProfileMapper interface {
	MapProfile(data ParsedProfile, _ []byte) (Profile, error)
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

func (o *StandardProviderOption) WithIssuer(issuer string) StandardProviderOption {
	return func(c *ProviderConfig) {
		c.Issuer = issuer
	}
}

func (o *StandardProviderOption) WithCallbackURL(callbackURL string) StandardProviderOption {
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

type endpoint struct {
	oauth2.Endpoint
	ProfileURL string
}

type StandardProvider struct {
	name     string
	endpoint endpoint
	scopes   []string
	config   ProviderConfig
	session  AuthSession
	mapper   ProfileMapper
}

func (p *StandardProvider) Configure(config ServiceConfig) {
	p.session = config.Session
	cbp := strings.Replace(
		config.CallbackPathTemplate, providerPlaceholder, p.name, -1)
	p.config.CallbackURL = strings.TrimSuffix(config.BaseURL, "/") +
		"/" + strings.Trim(cbp, "/")
}

func (p *StandardProvider) Name() string {
	return p.name
}

func (p *StandardProvider) Begin(w http.ResponseWriter, r *http.Request,
	config AuthConfig) *secutil.HTTPError {
	auth, err := p.session.Set(w, r, config)
	if err != nil {
		return secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to set session", err)
	}

	conf := p.configure()
	// We may want to support AccessTypeOffline if we ever want the server to return a refresh
	// token.  As it stands, a refresh token is not issued.
	loginURL := conf.AuthCodeURL(auth.State)
	http.Redirect(w, r, loginURL, http.StatusFound)
	return nil
}

func (p *StandardProvider) Finish(w http.ResponseWriter, r *http.Request) (
	*AuthResult, *secutil.HTTPError) {
	receivedState := r.URL.Query().Get("state")
	if receivedState == "" {
		return nil, secutil.NewHTTPError(http.StatusBadRequest, "state missing", nil)
	}

	session, err := p.session.Get(r)
	if err != nil {
		return nil, secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to get token", err)
	} else if session.State != receivedState {
		return nil, secutil.NewHTTPError(http.StatusInternalServerError,
			"unexpected state", nil)
	} else if err = p.session.Del(w); err != nil {
		// log.Printf("failed to delete auth session: %s", err.Error())
	}

	conf := p.configure()
	token, err := conf.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		return nil, secutil.NewHTTPError(http.StatusBadRequest, "exchange failed", err)
	}

	client := conf.Client(context.Background(), token)
	preq, err := client.Get(p.endpoint.ProfileURL)
	if err != nil {
		return nil, secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to get profile", err)
	}

	defer func() {
		if e := preq.Body.Close(); e != nil {
			// log.Printf("failed to close response body: %s", e.Error())
		}
	}()

	byteProfile, err := io.ReadAll(preq.Body)
	if err != nil {
		return nil, secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to read profile", err)
	}

	mappedProfile := map[string]interface{}{}
	if err := json.Unmarshal(byteProfile, &mappedProfile); err != nil {
		return nil, secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to unmarshal profile", err)
	}

	profile, err := p.mapper.MapProfile(mappedProfile, byteProfile)
	if err != nil {
		return nil, secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to map profile", err)
	}

	return &AuthResult{
		Provider:    p.name,
		Profile:     profile,
		Token:       *token,
		RedirectURL: session.RedirectURL}, nil
}

func (p *StandardProvider) configure() oauth2.Config {
	return oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Endpoint:     p.endpoint.Endpoint,
		Scopes:       p.scopes,
		RedirectURL:  p.config.CallbackURL,
	}
}
