package session

import (
	"fmt"
	"net/http"
	"time"

	"github.com/midsbie/authagon/oauth2"
	"github.com/midsbie/authagon/secutil"
	"github.com/midsbie/authagon/store"
)

const (
	defaultSessionIDKey    = "sid"
	defaultSessionDuration = 24 * time.Hour
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

func (s *SessionCtl) Set(w http.ResponseWriter, a oauth2.AuthResult) (string, error) {
	sid, err := secutil.RandomToken(32)
	if err != nil {
		return "", err
	}

	if err = s.browserStore.Set(w, s.sessionIDKey, sid, s.sessionDuration); err != nil {
		return "", fmt.Errorf("failed to persist session ID in browser store: %w", err)
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
	return "", fmt.Errorf("failed to persist session in store: %w", err)
}

func (s *SessionCtl) Get(r *http.Request) (oauth2.AuthResult, error) {
	sid, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return oauth2.AuthResult{}, fmt.Errorf("not authenticated")
	} else if ab, err := s.sessionStore.Get(sid); err != nil {
		return oauth2.AuthResult{}, fmt.Errorf("session not found: %s", sid)
	} else if a, ok := ab.(oauth2.AuthResult); ok {
		return a, nil
	}

	return oauth2.AuthResult{}, fmt.Errorf("failed to convert session: %s", sid)
}

func (s *SessionCtl) Exists(r *http.Request) bool {
	sid, err := s.browserStore.Get(r, s.sessionIDKey)
	return err == nil && sid != "" && s.sessionStore.Exists(sid)
}

func (s *SessionCtl) Del(w http.ResponseWriter, r *http.Request) error {
	sid, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		return fmt.Errorf("not authenticated")
	} else if err := s.sessionStore.Del(sid); err != nil {
		return fmt.Errorf("failed to delete session from store: %w", err)
	} else if err := s.browserStore.Del(w, s.sessionIDKey); err != nil {
		return fmt.Errorf("failed to delete browser session: %w", err)
	}

	return nil
}
