package store

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewCookieStoreDefaults(t *testing.T) {
	t.Parallel()

	cs := NewCookieStore()
	if cs.path != defaultPath {
		t.Errorf("path = %q, want %q", cs.path, defaultPath)
	}
	if cs.domain != "" {
		t.Errorf("domain = %q, want empty", cs.domain)
	}
	if !cs.httpOnly {
		t.Errorf("httpOnly = %v, want true", cs.httpOnly)
	}
	if !cs.secure {
		t.Errorf("secure = %v, want true", cs.secure)
	}
	if cs.sameSite != http.SameSiteDefaultMode {
		t.Errorf("sameSite = %v, want %v", cs.sameSite, http.SameSiteDefaultMode)
	}
}

func TestNewCookieStoreWithOptions(t *testing.T) {
	t.Parallel()

	cs := NewCookieStore(
		WithPath("/app"),
		WithDomain("example.com"),
		WithHTTPOnly(false),
		WithSecure(false),
		WithSameSite(http.SameSiteStrictMode),
	)

	if cs.path != "/app" {
		t.Errorf("path = %q, want %q", cs.path, "/app")
	}
	if cs.domain != "example.com" {
		t.Errorf("domain = %q, want %q", cs.domain, "example.com")
	}
	if cs.httpOnly {
		t.Errorf("httpOnly = %v, want false", cs.httpOnly)
	}
	if cs.secure {
		t.Errorf("secure = %v, want false", cs.secure)
	}
	if cs.sameSite != http.SameSiteStrictMode {
		t.Errorf("sameSite = %v, want %v", cs.sameSite, http.SameSiteStrictMode)
	}
}

func TestCookieStoreSet(t *testing.T) {
	t.Parallel()

	cs := NewCookieStore(WithSecure(false))
	w := httptest.NewRecorder()

	if err := cs.Set(w, "test-cookie", "test-value", time.Hour); err != nil {
		t.Fatalf("Set() error = %v, want nil", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set() cookies count = %d, want 1", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "test-cookie" {
		t.Errorf("cookie.Name = %q, want %q", cookie.Name, "test-cookie")
	}
	if cookie.Value != "test-value" {
		t.Errorf("cookie.Value = %q, want %q", cookie.Value, "test-value")
	}
	if cookie.Path != defaultPath {
		t.Errorf("cookie.Path = %q, want %q", cookie.Path, defaultPath)
	}
	if !cookie.HttpOnly {
		t.Errorf("cookie.HttpOnly = %v, want true", cookie.HttpOnly)
	}
	if cookie.Secure {
		t.Errorf("cookie.Secure = %v, want false", cookie.Secure)
	}
}

func TestCookieStoreGet(t *testing.T) {
	t.Parallel()

	cs := NewCookieStore()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "existing-cookie",
		Value: "existing-value",
	})

	value, err := cs.Get(r, "existing-cookie")
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	if value != "existing-value" {
		t.Errorf("Get() value = %q, want %q", value, "existing-value")
	}
}

func TestCookieStoreGetNotFound(t *testing.T) {
	t.Parallel()

	cs := NewCookieStore()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)

	value, err := cs.Get(r, "nonexistent-cookie")
	if err == nil {
		t.Fatalf("Get() error = nil, want ErrNotFound")
	}
	if value != "" {
		t.Errorf("Get() value = %q, want empty", value)
	}
}

func TestCookieStoreDel(t *testing.T) {
	t.Parallel()

	cs := NewCookieStore(WithSecure(false))
	w := httptest.NewRecorder()

	if err := cs.Del(w, "cookie-to-delete"); err != nil {
		t.Fatalf("Del() error = %v, want nil", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Del() cookies count = %d, want 1", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "cookie-to-delete" {
		t.Errorf("cookie.Name = %q, want %q", cookie.Name, "cookie-to-delete")
	}
	if cookie.Value != "" {
		t.Errorf("cookie.Value = %q, want empty", cookie.Value)
	}
	if !cookie.Expires.Before(time.Now()) {
		t.Errorf("cookie.Expires = %v, want time in the past", cookie.Expires)
	}
}

func TestCookieStoreRoundTrip(t *testing.T) {
	t.Parallel()

	cs := NewCookieStore(WithSecure(false))

	w := httptest.NewRecorder()
	if err := cs.Set(w, "roundtrip-cookie", "roundtrip-value", time.Hour); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}

	value, err := cs.Get(r, "roundtrip-cookie")
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	if value != "roundtrip-value" {
		t.Errorf("Get() value = %q, want %q", value, "roundtrip-value")
	}
}
