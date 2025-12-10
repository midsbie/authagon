package oauth2

import (
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type stubStateStore struct{}

func (stubStateStore) Set(w http.ResponseWriter, r *http.Request, cfg AuthConfig) (AuthState, error) {
	return AuthState{}, nil
}

func (stubStateStore) Get(r *http.Request) (AuthState, error) {
	return AuthState{}, nil
}

func (stubStateStore) Del(w http.ResponseWriter) error {
	return nil
}

type stubProvider struct {
	id         ProviderID
	config     oauth2.Config
	profileURL string
}

func (p *stubProvider) ID() ProviderID { return p.id }

func (p *stubProvider) Config(*serviceConfig) oauth2.Config {
	return p.config
}

func (p *stubProvider) ProfileURL() string {
	return p.profileURL
}

func (p *stubProvider) ExtractProfile(m ProfileMap, _ []byte) (Profile, error) {
	return Profile{}, nil
}

func TestNewService_DefaultsAndValidation(t *testing.T) {
	t.Parallel()

	svc, err := NewService(stubStateStore{})
	if err != nil {
		t.Fatalf("NewService() error = %v, want nil", err)
	}

	if svc.config.CallbackPathTemplate != DefaultCallbackPathTemplate {
		t.Fatalf("CallbackPathTemplate = %q, want %q",
			svc.config.CallbackPathTemplate, DefaultCallbackPathTemplate)
	}
	if svc.config.RedirectValidator == nil {
		t.Fatal("RedirectValidator is nil, want non-nil")
	}

	// Verify that a nil StateStore causes an error.
	if _, err := NewService(nil); err == nil {
		t.Fatal("NewService(nil) error = nil, want non-nil")
	}
}

func TestNewService_AppliesOptions(t *testing.T) {
	t.Parallel()

	customValidator := func(raw string) string {
		return "/custom"
	}

	state := stubStateStore{}

	svc, err := NewService(state,
		WithBaseURL("https://app.example"),
		WithCallbackPathTemplate("/cb/{provider}"),
		WithRedirectValidator(customValidator),
	)
	if err != nil {
		t.Fatalf("NewService(...) error = %v, want nil", err)
	}

	if svc.config.BaseURL != "https://app.example" {
		t.Fatalf("BaseURL = %q, want %q", svc.config.BaseURL, "https://app.example")
	}
	if svc.config.CallbackPathTemplate != "/cb/{provider}" {
		t.Fatalf("CallbackPathTemplate = %q, want %q",
			svc.config.CallbackPathTemplate, "/cb/{provider}")
	}
	if svc.config.StateStore == nil {
		t.Fatal("StateStore is nil, want non-nil")
	}
	if _, ok := svc.config.StateStore.(stubStateStore); !ok {
		t.Fatalf("StateStore type = %T, want stubStateStore", svc.config.StateStore)
	}
	if svc.config.RedirectValidator == nil {
		t.Fatal("RedirectValidator is nil, want non-nil")
	}
	if got := svc.config.RedirectValidator("http://evil.example"); got != "/custom" {
		t.Fatalf("RedirectValidator(...) = %q, want %q", got, "/custom")
	}
}

func TestOAuth2Service_RegisterAndProvider_Success(t *testing.T) {
	t.Parallel()

	svc, err := NewService(stubStateStore{}, WithBaseURL("https://app.example"))
	if err != nil {
		t.Fatalf("NewService() error = %v, want nil", err)
	}

	prov := &stubProvider{
		id:         ProviderID("custom"),
		config:     oauth2.Config{ClientID: "id"},
		profileURL: "https://provider.example/me",
	}

	svc.Register(prov)

	got, err := svc.Provider("custom")
	if err != nil {
		t.Fatalf("Provider(\"custom\") error = %v, want nil", err)
	}
	if got != prov {
		t.Fatalf("Provider(\"custom\") = %v, want %v", got, prov)
	}
}

func TestOAuth2Service_Provider_Errors(t *testing.T) {
	t.Parallel()

	svc, err := NewService(stubStateStore{}, WithBaseURL("https://app.example"))
	if err != nil {
		t.Fatalf("NewService() error = %v, want nil", err)
	}

	if _, err := svc.Provider(""); err != ErrNoProvider {
		t.Fatalf("Provider(\"\") error = %v, want %v", err, ErrNoProvider)
	}

	_, err = svc.Provider("missing")
	if err == nil {
		t.Fatal("Provider(\"missing\") error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "invalid provider name specified") {
		t.Fatalf("Provider(\"missing\") error = %q, want message about invalid provider name", err.Error())
	}
}

func TestOAuth2Service_NewAuthenticator_Success(t *testing.T) {
	t.Parallel()

	svc, err := NewService(stubStateStore{}, WithBaseURL("https://app.example"))
	if err != nil {
		t.Fatalf("NewService() error = %v, want nil", err)
	}

	prov := &stubProvider{
		id:         ProviderID("custom"),
		config:     oauth2.Config{ClientID: "id"},
		profileURL: "https://provider.example/me",
	}
	svc.Register(prov)

	a, err := svc.NewAuthenticator("custom")
	if err != nil {
		t.Fatalf("NewAuthenticator(\"custom\") error = %v, want nil", err)
	}
	if a == nil {
		t.Fatal("NewAuthenticator(\"custom\") = nil, want non-nil")
	}

	inner, ok := a.(*authenticator)
	if !ok {
		t.Fatalf("NewAuthenticator type = %T, want *authenticator", a)
	}
	if inner.svcConf != &svc.config {
		t.Fatalf("authenticator.svcConf = %p, want %p", inner.svcConf, &svc.config)
	}
	if _, ok := inner.state.(stubStateStore); !ok {
		t.Fatalf("authenticator.state type = %T, want stubStateStore", inner.state)
	}
	if inner.provider != prov {
		t.Fatalf("authenticator.provider = %v, want %v", inner.provider, prov)
	}
}

func TestOAuth2Service_NewAuthenticator_InvalidProvider(t *testing.T) {
	t.Parallel()

	svc, err := NewService(stubStateStore{}, WithBaseURL("https://app.example"))
	if err != nil {
		t.Fatalf("NewService() error = %v, want nil", err)
	}

	a, err := svc.NewAuthenticator("unknown")
	if err == nil {
		t.Fatal("NewAuthenticator(\"unknown\") error = nil, want non-nil")
	}
	if a != nil {
		t.Fatalf("NewAuthenticator(\"unknown\") = %v, want nil", a)
	}
}
