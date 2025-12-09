package oauth2

import "errors"

var (
	ErrNoProvider      = errors.New("no provider given")
	ErrStateMissing    = errors.New("state missing")
	ErrUnexpectedState = errors.New("unexpected state")
	ErrUnauthenticated = errors.New("not authenticated")
	// ErrTokenExpired indicates that a previously-issued handshake token
	// (e.g. in JWTStateStore) has expired and is no longer valid.
	ErrTokenExpired = errors.New("token expired")
)
