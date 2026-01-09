package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type authenticator struct {
	svcConf  *serviceConfig
	state    StateStore
	provider Provider
}

func (sa *authenticator) Start(w http.ResponseWriter, r *http.Request, config AuthConfig) error {
	validator := SanitizeRedirectURL
	if sa.svcConf != nil && sa.svcConf.RedirectValidator != nil {
		validator = sa.svcConf.RedirectValidator
	}
	config.RedirectURL = validator(config.RedirectURL)

	auth, err := sa.state.Set(w, r, config)
	if err != nil {
		return fmt.Errorf("failed to create authentication session: %w", err)
	}

	conf := sa.provider.Config(sa.svcConf)
	// We may want to support AccessTypeOffline if we ever want the server to receive a refresh
	// token. Currently we don’t request offline access, so providers such as Google typically
	// won’t issue a refresh token.
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

	session, err := sa.state.Get(r)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve authentication session: %w", err)
	} else if session.State != receivedState {
		return nil, ErrUnexpectedState
	} else if err = sa.state.Del(w); err != nil { //nolint:errcheck
		// TODO: log this error
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("code query parameter is missing")
	}

	conf := sa.provider.Config(sa.svcConf)
	token, err := conf.Exchange(r.Context(), code)
	if err != nil {
		return nil, fmt.Errorf("authentication exchange failed: %w", err)
	}

	client := conf.Client(r.Context(), token)
	preq, err := client.Get(sa.provider.ProfileURL())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch profile: %w", err)
	}
	if preq.StatusCode < 200 || preq.StatusCode >= 300 {
		preq.Body.Close()
		return nil, fmt.Errorf("profile request failed with status %d", preq.StatusCode)
	}

	defer preq.Body.Close()

	profileRaw, err := io.ReadAll(preq.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile: %w", err)
	}

	profileMap := map[string]any{}
	if err := json.Unmarshal(profileRaw, &profileMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profile: %w", err)
	}

	profile, err := sa.provider.ExtractProfile(profileMap, profileRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to extract profile: %w", err)
	}

	return &AuthResult{
		Provider:    string(sa.provider.ID()),
		Profile:     profile,
		Token:       *token,
		RedirectURL: session.RedirectURL}, nil
}
