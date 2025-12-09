// Package store provides generic storage abstractions used by the
// oauth2 package and example applications. It defines cookie-like
// browser storage and typed, TTL-aware session storage without any
// direct coupling to OAuth2 or HTTP handlers.
package store

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ErrNotFound is returned by BrowserStorer and SessionStorer when a
// requested key does not exist. It represents a “missing” value, not
// an internal failure.
var ErrNotFound = errors.New("store: not found")

type BrowserStorer interface {
	Set(w http.ResponseWriter, name, value string, duration time.Duration) error
	// Get retrieves the value of a browser-stored key.
	// It returns ErrNotFound when the key does not exist.
	Get(r *http.Request, name string) (string, error)
	Del(w http.ResponseWriter, name string) error
}

type SessionStorer[T any] interface {
	Set(ctx context.Context, sid string, value T, duration time.Duration) error
	Get(ctx context.Context, sid string) (T, error)
	Del(ctx context.Context, sid string) error
}
