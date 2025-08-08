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

type SessionControlReporter interface {
	SID() string
	store.SessionResultReporter
}

type sessionControlResult struct {
	store.SessionResultReporter
	sid string
}

func (scr *sessionControlResult) SID() string { return scr.sid }

// sessionCtlOption is the type for functional options.
type sessionCtlOption func(*SessionCtl)

func WithSessionIDKey(sessionIDKey string) sessionCtlOption {
	return func(sc *SessionCtl) {
		sc.sessionIDKey = sessionIDKey
	}
}

func WithSessionIDKeyLen(len int) sessionCtlOption {
	return func(sc *SessionCtl) {
		sc.sessionIDKeyLen = len
	}
}

func WithSessionDuration(sessionDuration time.Duration) sessionCtlOption {
	return func(sc *SessionCtl) {
		sc.sessionDuration = sessionDuration
	}
}

type SessionCtl struct {
	sessionIDKey    string
	sessionIDKeyLen int
	sessionDuration time.Duration
	browserStore    store.BrowserStorer
	sessionStore    store.SessionStorer
}

func NewSessionCtl(browserStore store.BrowserStorer, sessionStore store.SessionStorer,
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

func (s *SessionCtl) Set(ctx context.Context, w http.ResponseWriter,
	a AuthResult) (SessionControlReporter, error) {
	sid, err := RandomToken(s.sessionIDKeyLen)
	if err != nil {
		return nil, errors.New("failed to generate session ID")
	}

	if err = s.browserStore.Set(w, s.sessionIDKey, sid, s.sessionDuration); err != nil {
		return nil, fmt.Errorf("failed to create session cookie: %w", err)
	}

	resp, err := s.sessionStore.Set(ctx, sid, a, s.sessionDuration)
	if err != nil {
		if derr := s.browserStore.Del(w, s.sessionIDKey); derr != nil {
			err = errors.Join(err,
				fmt.Errorf("rollback delete cookie failed: %w", derr))
		}

		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &sessionControlResult{resp, sid}, nil
}

func (s *SessionCtl) Get(ctx context.Context, r *http.Request) (any, bool, error) {
	sid, ok, err := s.GetSessionID(r)
	if err != nil {
		return nil, false, err
	} else if !ok {
		return nil, false, nil
	}

	ab, ok, err := s.sessionStore.Get(ctx, sid)
	if err != nil {
		return AuthResult{}, false, fmt.Errorf(
			"error retrieving session (sid=%s) from store: %s", sid, err.Error())
	} else if !ok {
		return AuthResult{}, false, nil
	}

	return ab, true, nil
}

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

func (s *SessionCtl) GetSessionID(r *http.Request) (string, bool, error) {
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
