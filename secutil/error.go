package secutil

import (
	"net/http"
)

type HTTPError interface {
	error
	Status() int
	Unwrap() error
}

// httpError struct defines a structure for HTTP errors that includes a status code and a message.
type httpError struct {
	status  int
	message string
	err     error
}

// Error implements the error interface.
func (h *httpError) Error() string {
	return h.message
}

// Unwrap returns the underlying error.
func (h *httpError) Unwrap() error {
	return h.err
}

// Status implements the HTTPError interface. It returns the HTTP status code of the error.
func (h *httpError) Status() int {
	return h.status
}

// NewHTTPError creates a new httpError with the specified status, message, and underlying error.
func NewHTTPError(status int, message string, err error) *httpError {
	return &httpError{status: status, message: message, err: err}
}

// NewInternalServerError creates a new Internal Server Error (500) httpError.
func NewInternalServerError(msg string, err error) *httpError {
	return &httpError{
		status:  http.StatusInternalServerError,
		message: msg,
		err:     err,
	}
}

// NewBadRequestError creates a new BadRequest (400) httpError.
func NewBadRequestError(msg string, err error) *httpError {
	return &httpError{
		status:  http.StatusBadRequest,
		message: msg,
		err:     err,
	}
}

// NewUnauthorizedError creates a new Unauthorized (401) httpError.
func NewUnauthorizedError(msg string, err error) *httpError {
	return &httpError{
		status:  http.StatusUnauthorized,
		message: msg,
		err:     err,
	}
}

// NewNotFoundError creates a new NotFound (404) httpError.
func NewNotFoundError(msg string, err error) *httpError {
	return &httpError{
		status:  http.StatusNotFound,
		message: msg,
		err:     err,
	}
}

func ResolveHTTPError(err error, defaultErrFunc func() error) error {
	if err == nil {
		return nil
	} else if nerr, ok := err.(HTTPError); ok {
		return nerr
	}
	return defaultErrFunc()
}
