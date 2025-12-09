package oauth2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/midsbie/authagon/store"
)

func TestNewJWTStateStore_Validation(t *testing.T) {
	t.Parallel()

	cs := store.NewCookieStore()

	if _, err := NewJWTStateStore(nil, "secret"); err == nil {
		t.Fatalf("NewJWTStateStore(nil, ...) error = nil, want non-nil")
	}

	if _, err := NewJWTStateStore(cs, ""); err == nil {
		t.Fatalf("NewJWTStateStore(..., \"\") error = nil, want non-nil")
	}
}

func TestJWTStateStore_SetAndGet_Success(t *testing.T) {
	t.Parallel()

	cs := store.NewCookieStore(store.WithSecure(false))
	ss, err := NewJWTStateStore(cs, "test-secret", WithAudience("audience"), WithSessionKey("test_state"))
	if err != nil {
		t.Fatalf("NewJWTStateStore() error = %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/start", nil)

	cfg := AuthConfig{RedirectURL: "/after-login"}
	authState, err := ss.Set(w, r, cfg)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if authState.State == "" || authState.Nonce == "" {
		t.Fatalf("Set() returned empty State or Nonce: %#v", authState)
	}
	if authState.Audience != "audience" {
		t.Fatalf("Set() Audience = %q, want %q", authState.Audience, "audience")
	}
	if authState.RedirectURL != "/after-login" {
		t.Fatalf("Set() RedirectURL = %q, want %q", authState.RedirectURL, "/after-login")
	}

	// Simulate the browser sending the state cookie back.
	r2 := httptest.NewRequest(http.MethodGet, "http://example.test/callback", nil)
	for _, c := range w.Result().Cookies() {
		r2.AddCookie(c)
	}

	got, err := ss.Get(r2)
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	if got.State != authState.State {
		t.Errorf("Get() State = %q, want %q", got.State, authState.State)
	}
	if got.Nonce != authState.Nonce {
		t.Errorf("Get() Nonce = %q, want %q", got.Nonce, authState.Nonce)
	}
	if got.Audience != authState.Audience {
		t.Errorf("Get() Audience = %q, want %q", got.Audience, authState.Audience)
	}
	if got.RedirectURL != authState.RedirectURL {
		t.Errorf("Get() RedirectURL = %q, want %q", got.RedirectURL, authState.RedirectURL)
	}
}

func TestJWTStateStore_GetMissingCookie(t *testing.T) {
	t.Parallel()

	cs := store.NewCookieStore()
	ss, err := NewJWTStateStore(cs, "test-secret")
	if err != nil {
		t.Fatalf("NewJWTStateStore() error = %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.test/callback", nil)
	_, err = ss.Get(r)
	if err != ErrUnauthenticated {
		t.Fatalf("Get() error = %v, want ErrUnauthenticated", err)
	}
}

func TestJWTStateStore_GetAudienceMismatch(t *testing.T) {
	t.Parallel()

	cs := store.NewCookieStore(store.WithSecure(false))

	// Store with one audience to write the cookie.
	writerStore, err := NewJWTStateStore(cs, "test-secret", WithAudience("expected"))
	if err != nil {
		t.Fatalf("NewJWTStateStore() error = %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/start", nil)
	if _, err := writerStore.Set(w, r, AuthConfig{}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Reader with different audience to trigger mismatch.
	readerStore, err := NewJWTStateStore(cs, "test-secret", WithAudience("other"))
	if err != nil {
		t.Fatalf("NewJWTStateStore() (reader) error = %v", err)
	}

	r2 := httptest.NewRequest(http.MethodGet, "http://example.test/callback", nil)
	for _, c := range w.Result().Cookies() {
		r2.AddCookie(c)
	}

	_, err = readerStore.Get(r2)
	if err == nil || !strings.Contains(err.Error(), "audience not allowed") {
		t.Fatalf("Get() error = %v, want audience mismatch error", err)
	}
}

func TestJWTStateStore_GetExpiredToken(t *testing.T) {
	t.Parallel()

	cs := store.NewCookieStore(store.WithSecure(false))
	ss, err := NewJWTStateStore(cs, "test-secret",
		WithTokenDuration(-1*time.Minute))
	if err != nil {
		t.Fatalf("NewJWTStateStore() error = %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/start", nil)
	if _, err := ss.Set(w, r, AuthConfig{}); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	r2 := httptest.NewRequest(http.MethodGet, "http://example.test/callback", nil)
	for _, c := range w.Result().Cookies() {
		r2.AddCookie(c)
	}

	_, err = ss.Get(r2)
	if err == nil {
		t.Fatalf("Get() error = nil, want ErrTokenExpired")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Get() error = %v, want ErrTokenExpired", err)
	}
}

func TestJWTStateStore_Del(t *testing.T) {
	t.Parallel()

	cs := store.NewCookieStore(store.WithSecure(false))
	ss, err := NewJWTStateStore(cs, "test-secret")
	if err != nil {
		t.Fatalf("NewJWTStateStore() error = %v", err)
	}

	w := httptest.NewRecorder()
	if err := ss.Del(w); err != nil {
		t.Fatalf("Del() error = %v, want nil", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Del() cookies count = %d, want 1", len(cookies))
	}
	if cookies[0].Name == "" {
		t.Fatalf("Del() cookie name empty, want non-empty")
	}
	if cookies[0].Value != "" {
		t.Errorf("Del() cookie.Value = %q, want empty", cookies[0].Value)
	}
	if !cookies[0].Expires.Before(time.Now()) {
		t.Errorf("Del() cookie.Expires = %v, want time in the past", cookies[0].Expires)
	}
}
