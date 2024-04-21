package store

import (
	"context"
	"net/http"
	"time"
)

type SessionCreationResult int

const (
	SessionCreatedExistingAccount SessionCreationResult = iota
	SessionCreatedNewAccount
)

type setSessionResponse struct {
	sid    string
	result SessionCreationResult
}

// NewSetSessionResponse creates a new session response with the given details.
func NewSetSessionResponse(sid string, result SessionCreationResult) *setSessionResponse {
	return &setSessionResponse{
		sid:    sid,
		result: result,
	}
}

func (r *setSessionResponse) SID() string                   { return r.sid }
func (r *setSessionResponse) Result() SessionCreationResult { return r.result }

type SetSessionReporter interface {
	SID() string
	Result() SessionCreationResult
}

type BrowserStorer interface {
	Set(w http.ResponseWriter, name, value string, duration time.Duration) error
	Get(r *http.Request, name string) (string, bool, error)
	Del(w http.ResponseWriter, name string) error
}

type SessionStorer interface {
	Set(ctx context.Context, sid string, value interface{}, duration time.Duration) (
		SetSessionReporter, error)
	Get(ctx context.Context, sid string) (interface{}, bool, error)
	Del(ctx context.Context, sid string) error
}
