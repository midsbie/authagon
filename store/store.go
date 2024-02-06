package store

import (
	"net/http"
	"time"
)

type BrowserStore interface {
	Set(w http.ResponseWriter, name, value string, duration time.Duration) error
	Get(r *http.Request, name string) (string, error)
	Del(w http.ResponseWriter, name string) error
}

type SessionStore interface {
	Set(sid string, value interface{}, duration time.Duration) error
	Get(sid string) (interface{}, error)
	Exists(sid string) bool
	Del(sid string) error
}
