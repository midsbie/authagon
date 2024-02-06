package store

import (
	"net/http"
	"time"
)

const (
	defaultPath = "/"
)

// cookieStoreOption is the type for functional options.
type cookieStoreOption func(*CookieStore)

// WithPath sets the cookie path.
func WithPath(path string) cookieStoreOption {
	return func(cs *CookieStore) {
		cs.path = path
	}
}

// WithDomain sets the cookie domain.
func WithDomain(domain string) cookieStoreOption {
	return func(cs *CookieStore) {
		cs.domain = domain
	}
}

// WithHTTPOnly sets the HTTPOnly flag.
func WithHTTPOnly(httpOnly bool) cookieStoreOption {
	return func(cs *CookieStore) {
		cs.httpOnly = httpOnly
	}
}

// WithSecure sets the Secure flag.
func WithSecure(secure bool) cookieStoreOption {
	return func(cs *CookieStore) {
		cs.secure = secure
	}
}

// WithSameSite sets the SameSite option.
func WithSameSite(sameSite http.SameSite) cookieStoreOption {
	return func(cs *CookieStore) {
		cs.sameSite = sameSite
	}
}

// CookieStore implements the Store interface for cookies.
type CookieStore struct {
	path     string
	domain   string
	httpOnly bool
	secure   bool
	sameSite http.SameSite
}

// NewCookieStore initializes a new CookieStore with optional configurations.
func NewCookieStore(options ...cookieStoreOption) *CookieStore {
	cs := &CookieStore{
		path:     defaultPath,
		domain:   "",
		httpOnly: true,
		secure:   true,
		sameSite: http.SameSiteDefaultMode,
	}
	for _, option := range options {
		option(cs)
	}
	return cs
}

// Set writes a cookie with the specified name, value and duration to the http.ResponseWriter.  The
// cookie is configured with the domain, duration, HttpOnly, Secure, and SameSite settings specified
// during the CookieStore's creation. The cookie's expiration is set based on the duration.
func (cs *CookieStore) Set(w http.ResponseWriter, name, value string, duration time.Duration) error {
	expiration := time.Now().Add(duration)
	cs.setCookie(w, name, value, expiration)
	return nil
}

// Get retrieves the value of a cookie with the specified name from the *http.Request.  This method
// is used to access cookie values sent by the client in HTTP requests.
func (cs *CookieStore) Get(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// Del deletes a cookie with the specified name by setting its expiration date to a time in the
// past. This method instructs the client's browser to remove the cookie immediately.  The cookie is
// identified by its name, and the deletion settings match the domain, path, HttpOnly, Secure, and
// SameSite configuration of the CookieStore.
func (cs *CookieStore) Del(w http.ResponseWriter, name string) error {
	cs.setCookie(w, name, "", time.Unix(0, 0))
	return nil
}

// setCookie is a private helper function to configure and set a cookie.
func (cs *CookieStore) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Expires:  expires,
		Path:     cs.path,
		Domain:   cs.domain,
		HttpOnly: cs.httpOnly,
		Secure:   cs.secure,
		SameSite: cs.sameSite,
	}
	http.SetCookie(w, cookie)
}
