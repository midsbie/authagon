package store

import (
	"net/http"
	"time"
)

type BrowserStorer interface {
	Set(w http.ResponseWriter, name, value string, duration time.Duration) error
	Get(r *http.Request, name string) (string, bool, error)
	Del(w http.ResponseWriter, name string) error
}

type SessionStorer interface {
	Set(sid string, value interface{}, duration time.Duration) error
	Get(sid string) (interface{}, bool, error)
	Del(sid string) error
}
