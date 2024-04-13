package oauth2

import "errors"

var (
	ErrStateMissing    = errors.New("state missing")
	ErrUnexpectedState = errors.New("unexpected state")
	ErrUnauthenticated = errors.New("not authenticated")
)
