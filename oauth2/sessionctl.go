package oauth2

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/midsbie/authagon/store"
)

const (
	DefaultSessionIDKey    = "sid"
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
	browserStore    store.BrowserStorer
	sessionStore    store.SessionStorer
}

func NewSessionCtl(browserStore store.BrowserStorer, sessionStore store.SessionStorer,
	options ...sessionCtlOption) *SessionCtl {
	sc := &SessionCtl{
		sessionIDKey:    DefaultSessionIDKey,
		sessionDuration: defaultSessionDuration,
		browserStore:    browserStore,
		sessionStore:    sessionStore}

	for _, option := range options {
		option(sc)
	}
	return sc
}

func (s *SessionCtl) Set(w http.ResponseWriter, a AuthResult) (string, error) {
	sid, err := RandomToken(defaultSessionIdLength)
	if err != nil {
		return "", errors.New("failed to generate session ID")
	}

	if err = s.browserStore.Set(w, s.sessionIDKey, sid, s.sessionDuration); err != nil {
		return "", fmt.Errorf("failed to create session cookie: %w", err)
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
	return "", fmt.Errorf("failed to create session: %w", err)
}

func (s *SessionCtl) Get(r *http.Request) (interface{}, error) {
	sid, ok, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return false, err
	} else if !ok {
		return false, ErrUnauthenticated
	}

	ab, err := s.sessionStore.Get(sid)
	if err != nil {
		return AuthResult{}, fmt.Errorf("failed to retrieve session: %w", err)
	}

	return ab, nil
}

func (s *SessionCtl) Exists(r *http.Request) (bool, error) {
	sid, ok, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return false, err
	} else if !ok {
		return false, nil
	}

	ok, err = s.sessionStore.Exists(sid)
	if err != nil {
		return false, fmt.Errorf("failed to query session: %w", err)
	}
	return ok, nil
}

func (s *SessionCtl) Del(w http.ResponseWriter, r *http.Request) error {
	sid, ok, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return err
	} else if !ok {
		return ErrUnauthenticated
	}

	if err = s.sessionStore.Del(sid); err != nil {
		return fmt.Errorf("failed to delete session (%s): %w", sid, err)
	} else if err = s.browserStore.Del(w, s.sessionIDKey); err != nil {
		return fmt.Errorf("failed to delete session cookie (%s): %w", sid, err)
	}

	return nil
}

func (s *SessionCtl) getSessionID(r *http.Request) (string, bool, error) {
	sid, ok, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return "", false, fmt.Errorf("failed to retrieve session ID: %w", err)
	} else if !ok {
		return "", false, nil
	} else if sid == "" {
		return "", false, fmt.Errorf("invalid session ID")
	}

	return sid, true, nil
}
