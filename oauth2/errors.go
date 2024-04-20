package oauth2

import "errors"

var (
	ErrNoProvider      = errors.New("no provider given")
	ErrStateMissing    = errors.New("state missing")
	ErrUnexpectedState = errors.New("unexpected state")
	ErrUnauthenticated = errors.New("not authenticated")
)
