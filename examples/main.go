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
	"github.com/midsbie/authagon/secutil"
	"github.com/midsbie/authagon/store"
)

const (
	port             = "8081"
	jwtSessionSecret = "foobarbaz"
	audience         = "authagon"
)

type ProviderRegistry struct {
	Providers    []string
	ProvidersMap map[string]string
}

func main() {
	googleProvider := oauth2.NewGoogle(
		os.Getenv("AUTH_OAUTH_PROVIDER_GOOGLE_KEY"),
		os.Getenv("AUTH_OAUTH_PROVIDER_GOOGLE_SECRET"))

	cookieStore := store.NewCookieStore(store.WithSecure(false))
	jwts, err := oauth2.NewJWTSession(cookieStore, jwtSessionSecret,
		oauth2.WithAudience(audience))
	if err != nil {
		panic(fmt.Errorf("failed to create auth session: %w", err))
	}

	svc := oauth2.NewService(oauth2.ServiceConfig{
		BaseURL: "http://localhost:" + port,
		Session: jwts,
	})
	svc.Register(googleProvider)

	sessionStore := store.NewMemoryStore()
	sessionCtl := oauth2.NewSessionCtl(cookieStore, sessionStore)
	providerRegistry := getProviderRegistry()

	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if ok, err := sessionCtl.Exists(r); err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		} else if ok {
			t, _ := template.New("authenticated").Parse(indexAuthTpl)
			t.Execute(w, providerRegistry)
			return
		}

		t, err := template.New("index").Parse(indexAnonTpl)
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		if err := t.Execute(w, providerRegistry); err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
	})

	r.Get("/auth/{provider}", func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provider")
		prov, err := svc.GetProvider(name)
		if err != nil {
			http.Error(w, "Provider not found", http.StatusNotFound)
			return
		}

		config := oauth2.AuthConfig{
			Audience:    audience,
			RedirectURL: r.URL.Query().Get("redirect_to"),
		}
		if err := prov.Begin(w, r, config); err != nil {
			handleError(err, w)
		}
	})

	r.Get("/auth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "provider")
		prov, err := svc.GetProvider(name)
		if err != nil {
			http.Error(w, "Provider not found", http.StatusNotFound)
			return
		}

		result, err := prov.Finish(w, r)
		if err != nil {
			handleError(err, w)
			return
		}

		if sid, err := sessionCtl.Set(w, *result); err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		} else {
			fmt.Printf("Session created: %s\n", sid)
		}

		if result.RedirectURL != "" {
			http.Redirect(w, r, result.RedirectURL, http.StatusTemporaryRedirect)
		}
	})

	r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
		sess, err := sessionCtl.Get(r)
		if err != nil {
			handleError(err, w)
			return
		}

		t, err := template.New("profile").Parse(profileTpl)
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		if err := t.Execute(w, sess); err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
	})

	r.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		if err := sessionCtl.Del(w, r); err != nil {
			handleError(err, w)
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
		"google": "Google",
	}

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return &ProviderRegistry{Providers: keys, ProvidersMap: m}
}

func handleError(err error, w http.ResponseWriter) {
	if err == nil {
		return
	} else if nerr, ok := err.(secutil.HTTPError); ok {
		if werr := nerr.Unwrap(); werr != nil {
			log.Printf("%d %s: %s", nerr.Status(), nerr.Error(), werr.Error())
		} else {
			log.Printf("%d %s", nerr.Status(), nerr.Error())
		}
		http.Error(w, nerr.Error(), nerr.Status())
		return
	}

	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

var indexAnonTpl = `
{{range $key,$value:=.Providers}}
    <p><a href="/auth/{{$value}}?redirect_to=/">Log in with {{index $.ProvidersMap $value}}</a></p>
{{end}}
`

var indexAuthTpl = `
<p><strong>[Authenticated]</strong> <a href="/logout">Log out</a></p>
<p>View <a href="/profile">profile</a></p>
`

var profileTpl = `
<p><a href="/">Home</a> | <a href="/logout">Log out</a></p>
<p>ID: <code>{{.Profile.ID}}</code></p>
<p>Name: {{.Profile.FirstName}} {{.Profile.LastName}} ({{.Profile.Name}})</p>
<p>Email: <code>{{.Profile.Email}}</code></p>
<p>Picture URL: <a href="{{.Profile.PictureURL}}"><img src="{{.Profile.PictureURL}}"></a></p>
<p>AccessToken: <code>{{.Token.AccessToken}}</code></p>
<p>ExpiresAt: {{.Token.Expiry}}</p>
<p>RefreshToken: <code>{{.Token.RefreshToken}}</code></p>
`
