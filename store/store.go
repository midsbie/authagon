package store

import (
	"context"
	"net/http"
	"time"
)

type sessionResult struct {
	created bool
}

func NewSessionResult(created bool) *sessionResult {
	return &sessionResult{
		created: created,
	}
}

func (sr *sessionResult) SessionCreated() bool { return sr.created }

type SessionResultReporter interface {
	SessionCreated() bool
}

type BrowserStorer interface {
	Set(w http.ResponseWriter, name, value string, duration time.Duration) error
	Get(r *http.Request, name string) (string, bool, error)
	Del(w http.ResponseWriter, name string) error
}

type SessionStorer interface {
	Set(ctx context.Context, sid string, value interface{}, duration time.Duration) (
		SessionResultReporter, error)
	Get(ctx context.Context, sid string) (interface{}, bool, error)
	Del(ctx context.Context, sid string) error
}
