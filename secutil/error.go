package secutil

import (
	"errors"
	"fmt"
)

type HTTPError struct {
	Status      int
	Message     string
	InternalErr error
}

// Error implements the Error interface.
func (e *HTTPError) Error() string {
	return e.Message
}

// NewHTTPError creates a new HTTPError instance.
func NewHTTPError(status int, message string, internalErr error) *HTTPError {
	return &HTTPError{Status: status, Message: message, InternalErr: internalErr}
}

// Wrap creates a new HTTPError instance, transitioning from the prior approach of using a single
// `error` to wrap both a user-friendly message and an internal error. Before HTTPError, errors were
// wrapped with `fmt.Errorf`, combining a message (now `Message`) and an underlying error
// (`InternalErr`) into one. HTTPError separates these for clearer HTTP response handling: `Message`
// for client-facing communication and `InternalErr` for internal logging or processing. Wrap
// preserves this separation, making it suitable for HTTP scenarios where both types of error
// information are valuable.
func (e *HTTPError) Wrap() error {
	if e.InternalErr != nil {
		return fmt.Errorf("%s: %w", e.Message, e.InternalErr)
	}

	return errors.New(e.Message)
}

// Unwrap provides compatibility with errors.Unwrap by returning the embedded error.
func (e *HTTPError) Unwrap() error {
	return e.InternalErr
}
