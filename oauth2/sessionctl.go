package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/midsbie/authagon/store"
)

const (
	DefaultSessionIDKey    = "sid"
	defaultSessionDuration = 24 * time.Hour
	defaultSessionIDLength = 32
)

// sessionCtlOption is the type for functional options.
type sessionCtlOption func(*SessionCtl)

func WithSessionIDKey(sessionIDKey string) sessionCtlOption {
	return func(sc *SessionCtl) {
		sc.sessionIDKey = sessionIDKey
	}
}

func WithSessionIDKeyLen(length int) sessionCtlOption {
	return func(sc *SessionCtl) {
		sc.sessionIDKeyLen = length
	}
}

func WithSessionDuration(sessionDuration time.Duration) sessionCtlOption {
	return func(sc *SessionCtl) {
		sc.sessionDuration = sessionDuration
	}
}

// SessionCtl manages long-lived application sessions of AuthResult.
//
// It is explicitly separate from OAuth2/OIDC handshake state, which is handled via the StateStore
// interface. SessionCtl stores a session ID in a BrowserStorer-backed cookie and the corresponding
// AuthResult in a SessionStorer[AuthResult], allowing HTTP handlers to distinguish unauthenticated
// callers from internal failures. It is typically constructed with a CookieStore for browser
// storage and a SessionStorer[AuthResult] such as MemoryStore[AuthResult] for the backing store.
type SessionCtl struct {
	sessionIDKey    string
	sessionIDKeyLen int
	sessionDuration time.Duration
	browserStore    store.BrowserStorer
	sessionStore    store.SessionStorer[AuthResult]
}

// NewSessionCtl constructs a SessionCtl that uses the provided BrowserStorer for the session ID
// cookie and SessionStorer[AuthResult] for backing session data. Functional options can override
// the cookie key, session ID length, and session duration.
func NewSessionCtl(browserStore store.BrowserStorer, sessionStore store.SessionStorer[AuthResult],
	options ...sessionCtlOption) *SessionCtl {
	sc := &SessionCtl{
		sessionIDKey:    DefaultSessionIDKey,
		sessionIDKeyLen: defaultSessionIDLength,
		sessionDuration: defaultSessionDuration,
		browserStore:    browserStore,
		sessionStore:    sessionStore}

	for _, option := range options {
		option(sc)
	}
	return sc
}

// Set creates a new session for the given AuthResult, writes the session ID to the BrowserStorer,
// and persists the value in the SessionStorer. It returns the new session ID or an error if session
// creation fails.
func (s *SessionCtl) Set(ctx context.Context, w http.ResponseWriter,
	a AuthResult) (string, error) {
	sid, err := RandomToken(s.sessionIDKeyLen)
	if err != nil {
		return "", errors.New("failed to generate session ID")
	}

	if err = s.browserStore.Set(w, s.sessionIDKey, sid, s.sessionDuration); err != nil {
		return "", fmt.Errorf("failed to create session cookie: %w", err)
	}

	if err = s.sessionStore.Set(ctx, sid, a, s.sessionDuration); err != nil {
		if derr := s.browserStore.Del(w, s.sessionIDKey); derr != nil {
			err = errors.Join(err,
				fmt.Errorf("rollback delete cookie failed: %w", derr))
		}

		return "", fmt.Errorf("failed to create session: %w", err)
	}

	return sid, nil
}

// Get retrieves the current AuthResult for the request.
// It returns:
// - (AuthResult{}, false, nil) when no valid session is present
// - (result, true, nil) when authenticated
// - a non-nil error for internal failures reading the cookie or backing store.
func (s *SessionCtl) Get(ctx context.Context, r *http.Request) (AuthResult, bool, error) {
	sid, ok, err := s.GetSessionID(r)
	if err != nil {
		return AuthResult{}, false, err
	} else if !ok {
		return AuthResult{}, false, nil
	}

	ab, err := s.sessionStore.Get(ctx, sid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return AuthResult{}, false, nil
		}

		return AuthResult{}, false, fmt.Errorf(
			"error retrieving session (sid=%s) from store: %s", sid, err.Error())
	}

	return ab, true, nil
}

// Del deletes the current session identified by the request. It removes the entry from the
// SessionStorer and clears the session ID cookie. If no valid session ID is present it returns
// ErrUnauthenticated.
func (s *SessionCtl) Del(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	sid, ok, err := s.GetSessionID(r)
	if err != nil {
		return err
	} else if !ok {
		return ErrUnauthenticated
	}

	if err = s.sessionStore.Del(ctx, sid); err != nil {
		return fmt.Errorf("failed to delete session (%s): %w", sid, err)
	} else if err = s.browserStore.Del(w, s.sessionIDKey); err != nil {
		return fmt.Errorf("failed to delete session cookie (%s): %w", sid, err)
	}

	return nil
}

// GetSessionID reads the session ID from the BrowserStorer-backed cookie.
// It returns:
// - (id, true, nil) when a non-empty ID is present
// - ("", false, nil) when no cookie is set
// - a non-nil error for other failures.
func (s *SessionCtl) GetSessionID(r *http.Request) (string, bool, error) {
	sid, err := s.browserStore.Get(r, s.sessionIDKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", false, nil
		}

		return "", false, fmt.Errorf("failed to retrieve session ID: %w", err)
	} else if sid == "" {
		return "", false, fmt.Errorf("invalid session ID")
	}

	return sid, true, nil
}
