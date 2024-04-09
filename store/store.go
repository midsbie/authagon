package store

import (
	"net/http"
	"time"
)

type BrowserStorer interface {
	Set(w http.ResponseWriter, name, value string, duration time.Duration) error
	Get(r *http.Request, name string) (string, error)
	Del(w http.ResponseWriter, name string) error
}

type SessionStorer interface {
	Exists(sid string) (bool, error)
	Set(sid string, value interface{}, duration time.Duration) error
	Get(sid string) (interface{}, error)
	Del(sid string) error
}
