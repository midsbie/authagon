package oauth2

import (
	"testing"

	"golang.org/x/oauth2"
)

func TestNewProvider_ConfigDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	spec := ProviderSpec{
		ID: ProviderID("custom"),
		Endpoints: ProviderEndpoints{
			OAuth2: oauth2.Endpoint{
				AuthURL:  "https://provider.example/auth",
				TokenURL: "https://provider.example/token",
			},
			ProfileURL: "https://provider.example/me",
		},
		DefaultScopes:  []string{"scope1", "scope2"},
		ExtractProfile: func(m ProfileMap, _ []byte) (Profile, error) { return Profile{}, nil },
	}

	cfg := ProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}

	p := NewProvider(spec, cfg)

	svcConf := &serviceConfig{
		BaseURL:              "https://app.example",
		CallbackPathTemplate: "/u/auth/{provider}/callback",
	}

	conf := p.Config(svcConf)
	if conf.ClientID != cfg.ClientID || conf.ClientSecret != cfg.ClientSecret {
		t.Fatalf("Config credentials mismatch: got (%q,%q), want (%q,%q)",
			conf.ClientID, conf.ClientSecret, cfg.ClientID, cfg.ClientSecret)
	}
	if conf.Endpoint.AuthURL != spec.Endpoints.OAuth2.AuthURL ||
		conf.Endpoint.TokenURL != spec.Endpoints.OAuth2.TokenURL {
		t.Fatalf("Config.Endpoint mismatch: got %+v, want %+v", conf.Endpoint, spec.Endpoints.OAuth2)
	}
	if got, want := conf.Scopes, spec.DefaultScopes; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("Config.Scopes = %#v, want %#v", got, want)
	}

	wantRedirect := "https://app.example/u/auth/custom/callback"
	if conf.RedirectURL != wantRedirect {
		t.Fatalf("Config.RedirectURL = %q, want %q", conf.RedirectURL, wantRedirect)
	}

	// Override scopes and callback URL via options.
	cfg2 := ProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}
	p2 := NewProvider(spec, cfg2,
		WithScopes("override1", "override2"),
		WithCallbackURL("https://override/cb"),
	)
	conf2 := p2.Config(svcConf)
	if got, want := conf2.Scopes, []string{"override1", "override2"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("Config.Scopes override = %#v, want %#v", got, want)
	}
	if conf2.RedirectURL != "https://override/cb" {
		t.Fatalf("Config.RedirectURL override = %q, want %q", conf2.RedirectURL, "https://override/cb")
	}
}

func TestNewProvider_IDProfileAndExtractor(t *testing.T) {
	t.Parallel()

	called := false
	spec := ProviderSpec{
		ID: ProviderID("acme"),
		Endpoints: ProviderEndpoints{
			OAuth2: oauth2.Endpoint{
				AuthURL:  "https://acme.test/auth",
				TokenURL: "https://acme.test/token",
			},
			ProfileURL: "https://acme.test/me",
		},
		DefaultScopes: []string{"openid"},
		ExtractProfile: func(m ProfileMap, raw []byte) (Profile, error) {
			called = true
			return Profile{ID: "user-1", Name: m.String("name")}, nil
		},
	}
	cfg := ProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
	}

	p := NewProvider(spec, cfg)
	if p.ID() != ProviderID("acme") {
		t.Fatalf("ID() = %q, want %q", p.ID(), ProviderID("acme"))
	}
	if p.ProfileURL() != spec.Endpoints.ProfileURL {
		t.Fatalf("ProfileURL() = %q, want %q", p.ProfileURL(), spec.Endpoints.ProfileURL)
	}

	profile, err := p.ExtractProfile(ProfileMap{"name": "Jane"}, nil)
	if err != nil {
		t.Fatalf("ExtractProfile() error = %v, want nil", err)
	}
	if !called {
		t.Fatal("ExtractProfile() did not invoke spec.ExtractProfile")
	}
	if profile.ID != "user-1" || profile.Name != "Jane" {
		t.Fatalf("ExtractProfile() profile = %#v, want ID=user-1, Name=Jane", profile)
	}
}

func TestNewProvider_PanicsOnMissingCredentials(t *testing.T) {
	t.Parallel()

	spec := ProviderSpec{
		ID: ProviderID("broken"),
		Endpoints: ProviderEndpoints{
			OAuth2: oauth2.Endpoint{
				AuthURL:  "https://broken/auth",
				TokenURL: "https://broken/token",
			},
		},
		DefaultScopes:  []string{"scope"},
		ExtractProfile: func(ProfileMap, []byte) (Profile, error) { return Profile{}, nil },
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewProvider() did not panic for missing credentials")
		}
	}()

	_ = NewProvider(spec, ProviderConfig{})
}

func TestNewCustomProvider(t *testing.T) {
	t.Parallel()

	specEndpoints := ProviderEndpoints{
		OAuth2: oauth2.Endpoint{
			AuthURL:  "https://custom/auth",
			TokenURL: "https://custom/token",
		},
		ProfileURL: "https://custom/me",
	}

	extractor := func(m ProfileMap, _ []byte) (Profile, error) {
		return Profile{ID: m.String("id")}, nil
	}

	cfg := ProviderConfig{
		ClientID:     "cid",
		ClientSecret: "secret",
	}

	p := NewCustomProvider(ProviderID("custom"), specEndpoints, []string{"a", "b"}, extractor, cfg)

	if p.ID() != ProviderID("custom") {
		t.Fatalf("ID() = %q, want %q", p.ID(), ProviderID("custom"))
	}
	if p.ProfileURL() != specEndpoints.ProfileURL {
		t.Fatalf("ProfileURL() = %q, want %q", p.ProfileURL(), specEndpoints.ProfileURL)
	}

	conf := p.Config(&serviceConfig{
		BaseURL:              "https://app.example",
		CallbackPathTemplate: "/cb/{provider}",
	})
	if conf.Endpoint.AuthURL != specEndpoints.OAuth2.AuthURL {
		t.Fatalf("Config.Endpoint.AuthURL = %q, want %q", conf.Endpoint.AuthURL, specEndpoints.OAuth2.AuthURL)
	}

	profile, err := p.ExtractProfile(ProfileMap{"id": "xyz"}, nil)
	if err != nil {
		t.Fatalf("ExtractProfile() error = %v, want nil", err)
	}
	if profile.ID != "xyz" {
		t.Fatalf("ExtractProfile() ID = %q, want %q", profile.ID, "xyz")
	}
}
