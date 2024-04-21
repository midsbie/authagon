package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type authenticator struct {
	svcConf  *ServiceConfig
	session  SessionManager
	provider Provider
}

func (sa *authenticator) Start(w http.ResponseWriter, r *http.Request, config AuthConfig) error {
	auth, err := sa.session.Set(w, r, config)
	if err != nil {
		return fmt.Errorf("failed to create authentication session: %w", err)
	}

	conf := sa.provider.Configure(sa.svcConf)
	// We may want to support AccessTypeOffline if we ever want the server to return a refresh
	// token.  As it stands, a refresh token is not issued.
	loginURL := conf.AuthCodeURL(auth.State)
	http.Redirect(w, r, loginURL, http.StatusFound)
	return nil
}

func (sa *authenticator) Complete(w http.ResponseWriter, r *http.Request) (
	*AuthResult, error) {
	receivedState := r.URL.Query().Get("state")
	if receivedState == "" {
		return nil, ErrStateMissing
	}

	session, err := sa.session.Get(r)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve authentication session: %w", err)
	} else if session.State != receivedState {
		return nil, ErrUnexpectedState
	} else if err = sa.session.Del(w); err != nil {
		// log.Printf("failed to delete auth session: %s", err.Error())
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("code query parameter is missing")
	}

	conf := sa.provider.Configure(sa.svcConf)
	token, err := conf.Exchange(r.Context(), code)
	if err != nil {
		return nil, fmt.Errorf("authentication exchance failed: %w", err)
	}

	client := conf.Client(r.Context(), token)
	preq, err := client.Get(sa.provider.Endpoints().ProfileURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch profile: %w", err)
	}

	defer func() {
		if e := preq.Body.Close(); e != nil {
			// log.Printf("failed to close response body: %s", e.Error())
		}
	}()

	profileRaw, err := io.ReadAll(preq.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile: %w", err)
	}

	profileMap := map[string]interface{}{}
	if err := json.Unmarshal(profileRaw, &profileMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profile: %w", err)
	}

	profile, err := sa.provider.ExtractProfile(profileMap, profileRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract profile: %w", err)
	}

	return &AuthResult{
		Provider:    sa.provider.Name(),
		Profile:     profile,
		Token:       *token,
		RedirectURL: session.RedirectURL}, nil
}
