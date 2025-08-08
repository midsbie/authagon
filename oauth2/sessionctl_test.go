package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/midsbie/authagon/store"
)

func newSessionCtlForTest() *SessionCtl {
	cs := store.NewCookieStore(
		store.WithSecure(false), // ok for tests
		store.WithHTTPOnly(true),
	)
	mem := store.NewMemoryStore()
	return NewSessionCtl(cs, mem,
		WithSessionIDKey("sid"),
		WithSessionIDKeyLen(16),
		WithSessionDuration(10*time.Minute),
	)
}

func attachResponseCookiesToRequest(rr *httptest.ResponseRecorder, r *http.Request) {
	for _, h := range rr.Result().Cookies() {
		r.AddCookie(h)
	}
}

type failingSessionStore struct{}

func (f *failingSessionStore) Set(ctx context.Context, sid string, value interface{},
	duration time.Duration) (store.SessionResultReporter, error) {
	return store.NewSessionResult(false), fmt.Errorf("boom: unable to persist session")
}

func (f *failingSessionStore) Get(ctx context.Context, sid string) (interface{}, bool, error) {
	return nil, false, fmt.Errorf("not implemented")
}

func (f *failingSessionStore) Del(ctx context.Context, sid string) error { return nil }

func TestSetAndGet_RoundTrip(t *testing.T) {
	sc := newSessionCtlForTest()

	// simulate initial login (Set)
	w := httptest.NewRecorder()
	ar := AuthResult{
		Provider: "google",
		Profile:  Profile{ID: "abc", Name: "Jane Roe"},
		Token:    oauth2.Token{},
		// RedirectURL isn't used by SessionCtl, but gets stored in session
		RedirectURL: "/",
	}
	ctx := context.Background()
	sr, err := sc.Set(ctx, w, ar)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if sr == nil || sr.SID() == "" {
		t.Fatalf("Set() did not return a valid session ID")
	}

	// simulate callback request that carries the cookie
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	attachResponseCookiesToRequest(w, r)

	// Get should retrieve the stored AuthResult from the session store
	got, ok, err := sc.Get(ctx, r)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatalf("Get() ok = false, want true")
	}

	gotAR, ok := got.(AuthResult)
	if !ok {
		t.Fatalf("Get() type assertion failed; got %T", got)
	}

	// Compare fields we expect to round-trip through the store
	want := AuthResult{
		Provider:    ar.Provider,
		Profile:     ar.Profile,
		Token:       ar.Token,
		RedirectURL: ar.RedirectURL,
	}
	if !reflect.DeepEqual(gotAR, want) {
		t.Fatalf("Get() mismatch:\n got: %#v\nwant: %#v", gotAR, want)
	}
}

func TestGetSessionID_NoCookie(t *testing.T) {
	sc := newSessionCtlForTest()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)

	sid, ok, err := sc.GetSessionID(r)
	if err != nil {
		t.Fatalf("GetSessionID() error = %v", err)
	}
	if ok {
		t.Fatalf("GetSessionID() ok = true; want false")
	}
	if sid != "" {
		t.Fatalf("GetSessionID() sid = %q; want empty", sid)
	}
}

func TestGetSessionID_EmptyCookieValue(t *testing.T) {
	// Build a request that carries an empty cookie value, which should be treated as invalid.
	sc := newSessionCtlForTest()
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.Header.Add("Cookie", "sid=") // empty value

	_, ok, err := sc.GetSessionID(r)
	if err == nil {
		t.Fatalf("GetSessionID() err = nil; want error for empty cookie value")
	}
	if ok {
		t.Fatalf("GetSessionID() ok = true; want false")
	}
	if !strings.Contains(err.Error(), "invalid session ID") {
		t.Fatalf("GetSessionID() unexpected error: %v", err)
	}
}

func TestSet_RollsBackCookieOnStoreFailure(t *testing.T) {
	// Use CookieStore + failing session store to trigger rollback path.
	cs := store.NewCookieStore(store.WithSecure(false))
	fs := &failingSessionStore{}
	sc := NewSessionCtl(cs, fs)

	w := httptest.NewRecorder()
	ctx := context.Background()
	_, err := sc.Set(ctx, w, AuthResult{})
	if err == nil {
		t.Fatalf("Set() err = nil; want failure from session store")
	}

	// Expect that after failure, a deletion cookie was sent (expires in the past).
	res := w.Result()
	var delFound bool
	for _, c := range res.Cookies() {
		if c.Name == DefaultSessionIDKey {
			// Deletion cookie should have an Expires in the past (Unix(0))
			if c.Expires.Before(time.Now().Add(-time.Minute)) {
				delFound = true
				break
			}
		}
	}
	if !delFound {
		t.Fatalf("Set() did not emit a deletion cookie after failure")
	}
}

func TestDel_RemovesSessionAndCookie(t *testing.T) {
	sc := newSessionCtlForTest()

	// First create a session
	w1 := httptest.NewRecorder()
	ctx := context.Background()
	sr, err := sc.Set(ctx, w1, AuthResult{Provider: "google"})
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if sr == nil || sr.SID() == "" {
		t.Fatalf("Set() did not return a valid session ID")
	}

	// Prepare a request carrying that cookie
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	attachResponseCookiesToRequest(w1, r)

	// Now delete it
	w2 := httptest.NewRecorder()
	if err := sc.Del(ctx, w2, r); err != nil {
		t.Fatalf("Del() error = %v", err)
	}

	// Response should include a deletion cookie
	var delFound bool
	for _, c := range w2.Result().Cookies() {
		if c.Name == DefaultSessionIDKey && c.Expires.Before(time.Now().Add(-time.Minute)) {
			delFound = true
			break
		}
	}
	if !delFound {
		t.Fatalf("Del() did not emit deletion cookie")
	}

	// Attempting to Get again should fail due to missing session in the store.
	// (Cookie still on the request object, but backing store entry should be gone.)
	_, ok, err := sc.Get(ctx, r)
	if err == nil || ok {
		t.Fatalf("Get() after Del() = (ok=%v, err=%v); want error and ok=false", ok, err)
	}
}
