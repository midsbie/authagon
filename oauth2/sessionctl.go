package oauth2

import (
	"fmt"
	"net/http"
	"time"

	"github.com/midsbie/authagon/secutil"
	"github.com/midsbie/authagon/store"
)

const (
	defaultSessionIDKey    = "sid"
	defaultSessionDuration = 24 * time.Hour
	defaultSessionIdLength = 32
)

// sessionCtlOption is the type for functional options.
type sessionCtlOption func(*SessionCtl)

func WithSessionIDKey(sessionIDKey string) sessionCtlOption {
	return func(sc *SessionCtl) {
		sc.sessionIDKey = sessionIDKey
	}
}

func WithSessionDuration(sessionDuration time.Duration) sessionCtlOption {
	return func(sc *SessionCtl) {
		sc.sessionDuration = sessionDuration
	}
}

type SessionCtl struct {
	sessionIDKey    string
	sessionDuration time.Duration
	browserStore    store.BrowserStore
	sessionStore    store.SessionStore
}

func NewSessionCtl(browserStore store.BrowserStore, sessionStore store.SessionStore,
	options ...sessionCtlOption) *SessionCtl {
	sc := &SessionCtl{
		sessionIDKey:    defaultSessionIDKey,
		sessionDuration: defaultSessionDuration,
		browserStore:    browserStore,
		sessionStore:    sessionStore}

	for _, option := range options {
		option(sc)
	}
	return sc
}

func (s *SessionCtl) Set(w http.ResponseWriter, a AuthResult) (string, *secutil.HTTPError) {
	sid, err := secutil.RandomToken(defaultSessionIdLength)
	if err != nil {
		return "", secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to generate session ID", err)
	}

	if err = s.browserStore.Set(w, s.sessionIDKey, sid, s.sessionDuration); err != nil {
		return "", secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to persist session ID in browser store", err)
	} else if err = s.sessionStore.Set(sid, a, s.sessionDuration); err == nil {
		return sid, nil
	}

	// Calling Set and then Del for the same cookie within the handling of a single request
	// results in the cookie being deleted (not stored) in the client's browser, as the final
	// state is determined by the last Set-Cookie header processed by the browser.
	//
	// In an ideal scenario, we should consider implementing a custom http.ResponseWriter that
	// buffers headers or offers methods for header manipulation.
	// ---
	// TODO: handle case where we fail to delete from the browser store, perhaps by logging a
	// warning?
	s.browserStore.Del(w, s.sessionIDKey)
	return "", secutil.NewHTTPError(http.StatusInternalServerError,
		"failed to persist session in store", err)
}

func (s *SessionCtl) Get(r *http.Request) (AuthResult, *secutil.HTTPError) {
	sid, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return AuthResult{}, secutil.NewHTTPError(
			http.StatusUnauthorized, "not authenticated", err)
	}

	ab, err := s.sessionStore.Get(sid)
	if err != nil {
		return AuthResult{}, secutil.NewHTTPError(
			http.StatusNotFound, "session not found", err)
	}

	a, ok := ab.(AuthResult)
	if !ok {
		return AuthResult{}, secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to convert session", fmt.Errorf("session ID: %s", sid))
	}

	return a, nil
}

func (s *SessionCtl) Exists(r *http.Request) (bool, error) {
	sid, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return false, err
	} else if sid == "" {
		return false, fmt.Errorf("invalid session ID")
	}

	ok, err := s.sessionStore.Exists(sid)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (s *SessionCtl) Del(w http.ResponseWriter, r *http.Request) *secutil.HTTPError {
	sid, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return secutil.NewHTTPError(http.StatusUnauthorized, "not authenticated", err)
	} else if err := s.sessionStore.Del(sid); err != nil {
		return secutil.NewHTTPError(http.StatusInternalServerError,
			"failed to delete session from store", err)
	} else if err := s.browserStore.Del(w, s.sessionIDKey); err != nil {
		return secutil.NewHTTPError(
			http.StatusInternalServerError, "failed to delete browser session", err)
	}

	return nil
}
