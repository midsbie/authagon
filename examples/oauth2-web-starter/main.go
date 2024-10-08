package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/midsbie/authagon/oauth2"
	"github.com/midsbie/authagon/store"
)

const (
	port             = "3000"
	jwtSessionSecret = "foobarbaz"
	audience         = "authagon"
)

type ProviderRegistry struct {
	Providers    []string
	ProvidersMap map[string]string
}

func main() {
	cookieStore := store.NewCookieStore(store.WithSecure(false))
	jwts, err := oauth2.NewJWTSessionManager(cookieStore, jwtSessionSecret,
		oauth2.WithAudience(audience))
	if err != nil {
		panic(fmt.Errorf("failed to create auth session: %w", err))
	}

	svc := oauth2.NewService(oauth2.ServiceConfig{
		BaseURL:        "http://localhost:" + port,
		SessionManager: jwts,
		// Customize this to match your settings.
		CallbackPathTemplate: oauth2.DefaultCallbackPathTemplate,
	})

	svc.Register(oauth2.NewGoogle(
		mustGetenv("AUTH_OAUTH_PROVIDER_GOOGLE_KEY"),
		mustGetenv("AUTH_OAUTH_PROVIDER_GOOGLE_SECRET")))
	svc.Register(oauth2.NewMicrosoft(
		mustGetenv("AUTH_OAUTH_PROVIDER_MICROSOFT_KEY"),
		mustGetenv("AUTH_OAUTH_PROVIDER_MICROSOFT_SECRET")))

	sessionStore := store.NewMemoryStore()
	sessionCtl := oauth2.NewSessionCtl(cookieStore, sessionStore)
	providerRegistry := getProviderRegistry()

	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if _, ok, err := sessionCtl.Get(r.Context(), r); err != nil {
			handleInternalError(err, w)
			return
		} else if ok {
			t, _ := template.New("authenticated").Parse(indexAuthTpl)
			t.Execute(w, providerRegistry)
			return
		}

		t, err := template.New("index").Parse(indexAnonTpl)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		if err := t.Execute(w, providerRegistry); err != nil {
			handleInternalError(err, w)
		}
	})

	r.Get("/u/auth/{provider}", func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provider")
		auth, err := svc.NewAuthenticator(name)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		config := oauth2.AuthConfig{
			Audience:    audience,
			RedirectURL: r.URL.Query().Get("redirect_to"),
		}

		if err := auth.Start(w, r, config); err != nil {
			handleInternalError(err, w)
		}
	})

	r.Get("/u/auth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provider")
		auth, err := svc.NewAuthenticator(name)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		result, err := auth.Complete(w, r)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		sid, err := sessionCtl.Set(r.Context(), w, *result)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		log.Printf("Session created: %s\n", sid)

		if result.RedirectURL != "" {
			http.Redirect(w, r, result.RedirectURL, http.StatusTemporaryRedirect)
		}
	})

	r.Get("/u/profile", func(w http.ResponseWriter, r *http.Request) {
		sess, ok, err := sessionCtl.Get(r.Context(), r)
		if err != nil {
			handleInternalError(err, w)
			return
		} else if !ok {
			http.Error(w, "Not Authenticated", http.StatusUnauthorized)
			return
		}

		t, err := template.New("profile").Parse(profileTpl)
		if err != nil {
			handleInternalError(err, w)
			return
		}

		if err := t.Execute(w, sess); err != nil {
			handleInternalError(err, w)
		}
	})

	r.Get("/u/logout", func(w http.ResponseWriter, r *http.Request) {
		if err := sessionCtl.Del(r.Context(), w, r); err != nil {
			handleInternalError(err, w)
			return
		}

		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})

	log.Println("listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func getProviderRegistry() *ProviderRegistry {
	m := map[string]string{
		"google":    "Google",
		"microsoft": "Microsoft",
	}

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return &ProviderRegistry{Providers: keys, ProvidersMap: m}
}

func handleInternalError(err error, w http.ResponseWriter) {
	log.Println(err.Error())
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("Env var %s required", key))
	}

	return v
}

var indexAnonTpl = `
{{range $key,$value:=.Providers}}
    <p><a href="/u/auth/{{$value}}?redirect_to=/">Log in with {{index $.ProvidersMap $value}}</a></p>
{{end}}
`

var indexAuthTpl = `
<p><strong>[Authenticated]</strong> <a href="/u/logout">Log out</a></p>
<p>View <a href="/u/profile">profile</a></p>
`

var profileTpl = `
<p><a href="/">Home</a> | <a href="/u/logout">Log out</a></p>
<p>ID: <code>{{.Profile.ID}}</code></p>
<p>Name: {{.Profile.FirstName}} {{.Profile.LastName}} ({{.Profile.Name}})</p>
<p>Email: <code>{{.Profile.Email}}</code></p>
<p>Picture URL: <a href="{{.Profile.PictureURL}}"><img src="{{.Profile.PictureURL}}"></a></p>
<p>AccessToken: <code>{{.Token.AccessToken}}</code></p>
<p>ExpiresAt: {{.Token.Expiry}}</p>
<p>RefreshToken: <code>{{.Token.RefreshToken}}</code></p>
`
