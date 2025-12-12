package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/midsbie/authagon/oauth2"
	"github.com/midsbie/authagon/store"
)

const (
	appSessionCookieName = "app_session_id"
	appSessionTTL        = 24 * time.Hour
)

type AppSession struct {
	UserID   string
	Provider string
	Profile  oauth2.Profile
}

type InMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]AppSession
}

func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: make(map[string]AppSession),
	}
}

func (s *InMemorySessionStore) Set(sid string, session AppSession) {
	s.mu.Lock()
	s.sessions[sid] = session
	s.mu.Unlock()
}

func (s *InMemorySessionStore) Get(sid string) (AppSession, bool) {
	s.mu.RLock()
	session, ok := s.sessions[sid]
	s.mu.RUnlock()
	return session, ok
}

func (s *InMemorySessionStore) Del(sid string) {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
}

func setAppSession(w http.ResponseWriter, store *InMemorySessionStore, session AppSession) (string, error) {
	sid, err := oauth2.RandomToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate app session ID: %w", err)
	}

	store.Set(sid, session)

	http.SetCookie(w, &http.Cookie{
		Name:     appSessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // set to true in production over HTTPS
		Expires:  time.Now().Add(appSessionTTL),
	})

	return sid, nil
}

func getAppSession(r *http.Request, store *InMemorySessionStore) (AppSession, bool, error) {
	cookie, err := r.Cookie(appSessionCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return AppSession{}, false, nil
		}
		return AppSession{}, false, fmt.Errorf("failed to read app session cookie: %w", err)
	}
	if cookie.Value == "" {
		return AppSession{}, false, nil
	}

	session, ok := store.Get(cookie.Value)
	return session, ok, nil
}

func clearAppSession(w http.ResponseWriter, r *http.Request, store *InMemorySessionStore) {
	cookie, err := r.Cookie(appSessionCookieName)
	if err == nil && cookie.Value != "" {
		store.Del(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     appSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Unix(0, 0),
	})
}

func main() {
	port := getenvOrDefault("APP_PORT", "3000")
	jwtSessionSecret := getenvOrPanic("JWT_SESSION_SECRET")
	audience := getenvOrDefault("JWT_AUDIENCE", "authagon-core-example")

	// Handshake state: JWTStateStore + CookieStore
	cookieStore := store.NewCookieStore(store.WithSecure(false)) // HTTPS-only in production
	jwtState, err := oauth2.NewJWTStateStore(cookieStore, jwtSessionSecret,
		oauth2.WithAudience(audience))
	if err != nil {
		log.Fatalf("failed to create JWTStateStore: %v", err)
	}

	// OAuth2 service with a single provider (Google for brevity)
	svc, err := oauth2.NewService(jwtState,
		oauth2.WithBaseURL("http://localhost:"+port))
	if err != nil {
		log.Fatalf("failed to create OAuth2Service: %v", err)
	}

	svc.Register(oauth2.NewGoogle(
		getenvOrPanic("AUTH_OAUTH_PROVIDER_GOOGLE_KEY"),
		getenvOrPanic("AUTH_OAUTH_PROVIDER_GOOGLE_SECRET"),
	))

	// Application-managed sessions (no SessionCtl)
	appSessions := NewInMemorySessionStore()

	tplIndex := template.Must(template.New("index").Parse(indexTpl))
	tplProfile := template.Must(template.New("profile").Parse(profileTpl))

	// Home page: show login link or greeting depending on app session
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, ok, err := getAppSession(r, appSessions)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		data := struct {
			Authenticated bool
			Session       AppSession
		}{
			Authenticated: ok,
			Session:       session,
		}

		if err := tplIndex.Execute(w, data); err != nil {
			handleInternalError(err, w)
			return
		}
	})

	// Start OAuth2 login with Google
	http.HandleFunc("/u/auth/google", func(w http.ResponseWriter, r *http.Request) {
		auth, err := svc.NewAuthenticator("google")
		if err != nil {
			handleInternalError(err, w)
			return
		}

		if err := auth.Start(w, r, oauth2.AuthConfig{
			RedirectURL: "/u/profile",
		}); err != nil {
			handleInternalError(err, w)
			return
		}
	})

	// OAuth2 callback: complete handshake, then create app session
	http.HandleFunc("/u/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		auth, err := svc.NewAuthenticator("google")
		if err != nil {
			handleInternalError(err, w)
			return
		}

		result, err := auth.Complete(w, r)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		appSess := AppSession{
			UserID:   result.Profile.ID,
			Provider: result.Provider,
			Profile:  result.Profile,
		}
		sid, err := setAppSession(w, appSessions, appSess)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		log.Printf("App session created: %s", sid)

		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
	})

	// Authenticated endpoint using app-managed sessions only
	http.HandleFunc("/u/profile", func(w http.ResponseWriter, r *http.Request) {
		session, ok, err := getAppSession(r, appSessions)
		if err != nil {
			handleInternalError(err, w)
			return
		}
		if !ok {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}

		if err := tplProfile.Execute(w, session); err != nil {
			handleInternalError(err, w)
			return
		}
	})

	// Log out: clear app session only (handshake state remains separate)
	http.HandleFunc("/u/logout", func(w http.ResponseWriter, r *http.Request) {
		clearAppSession(w, r, appSessions)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	log.Println("listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleInternalError(err error, w http.ResponseWriter) {
	log.Println(err.Error())
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

func getenvOrDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getenvOrPanic(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("Env var %s required", key))
	}
	return v
}

var indexTpl = `
<html>
  <body>
    {{if .Authenticated}}
      <p><strong>[Authenticated]</strong> via {{.Session.Provider}}</p>
      <p>Hello, {{.Session.Profile.Name}} (ID: {{.Session.Profile.ID}})</p>
      <p><a href="/u/profile">View profile</a> | <a href="/u/logout">Log out</a></p>
    {{else}}
      <p>You are not logged in.</p>
      <p><a href="/u/auth/google">Log in with Google</a></p>
    {{end}}
  </body>
</html>
`

var profileTpl = `
<html>
  <body>
    <p><a href="/">Home</a> | <a href="/u/logout">Log out</a></p>
    <p>ID: <code>{{.Profile.ID}}</code></p>
    <p>Name: {{.Profile.FirstName}} {{.Profile.LastName}} ({{.Profile.Name}})</p>
    <p>Email: <code>{{.Profile.Email}}</code></p>
    <p>Provider: <code>{{.Provider}}</code></p>
  </body>
</html>
`

