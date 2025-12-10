package oauth2

import (
	"testing"

	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

func TestGoogleSpecAndNewGoogle(t *testing.T) {
	t.Parallel()

	if GoogleSpec.ID != ProviderGoogle {
		t.Fatalf("GoogleSpec.ID = %q, want %q", GoogleSpec.ID, ProviderGoogle)
	}
	if GoogleSpec.Endpoints.OAuth2.AuthURL != google.Endpoint.AuthURL ||
		GoogleSpec.Endpoints.OAuth2.TokenURL != google.Endpoint.TokenURL {
		t.Fatalf("GoogleSpec endpoints mismatch: got %+v, want %+v",
			GoogleSpec.Endpoints.OAuth2, google.Endpoint)
	}
	if GoogleSpec.Endpoints.ProfileURL == "" {
		t.Fatal("GoogleSpec.Endpoints.ProfileURL is empty")
	}
	if len(GoogleSpec.DefaultScopes) == 0 {
		t.Fatal("GoogleSpec.DefaultScopes is empty")
	}

	// Verify NewGoogle wiring into Provider.
	p := NewGoogle("id", "secret")
	if p.ID() != ProviderGoogle {
		t.Fatalf("NewGoogle ID() = %q, want %q", p.ID(), ProviderGoogle)
	}
	if p.ProfileURL() != GoogleSpec.Endpoints.ProfileURL {
		t.Fatalf("NewGoogle ProfileURL() = %q, want %q", p.ProfileURL(), GoogleSpec.Endpoints.ProfileURL)
	}

	conf := p.Config(&serviceConfig{
		BaseURL:              "https://app.example",
		CallbackPathTemplate: "/u/auth/{provider}/callback",
	})
	if conf.ClientID != "id" || conf.ClientSecret != "secret" {
		t.Fatalf("NewGoogle Config credentials = (%q,%q), want (%q,%q)", conf.ClientID, conf.ClientSecret, "id", "secret")
	}
	if conf.Endpoint.AuthURL != google.Endpoint.AuthURL || conf.Endpoint.TokenURL != google.Endpoint.TokenURL {
		t.Fatalf("NewGoogle Config.Endpoint mismatch: got %+v, want %+v", conf.Endpoint, google.Endpoint)
	}
}

func TestGoogleExtractProfile(t *testing.T) {
	t.Parallel()

	data := ProfileMap{
		"sub":         "123",
		"name":        "Jane Doe",
		"given_name":  "Jane",
		"family_name": "Doe",
		"email":       "jane@example.com",
		"picture":     "https://example.com/pic.jpg",
	}

	p, err := googleExtractProfile(data, nil)
	if err != nil {
		t.Fatalf("googleExtractProfile() error = %v, want nil", err)
	}
	if p.CanonicalID != "123" {
		t.Fatalf("CanonicalID = %q, want %q", p.CanonicalID, "123")
	}
	if p.Name != "Jane Doe" || p.FirstName != "Jane" || p.LastName != "Doe" {
		t.Fatalf("Name fields = %#v, want Jane / Jane / Doe", p)
	}
	if p.Email != "jane@example.com" {
		t.Fatalf("Email = %q, want %q", p.Email, "jane@example.com")
	}
	if p.PictureURL != "https://example.com/pic.jpg" {
		t.Fatalf("PictureURL = %q, want %q", p.PictureURL, "https://example.com/pic.jpg")
	}
	if p.ID == "" {
		t.Fatal("ID should not be empty")
	}
}

func TestMicrosoftSpecAndNewMicrosoft(t *testing.T) {
	t.Parallel()

	if MicrosoftSpec.ID != ProviderMicrosoft {
		t.Fatalf("MicrosoftSpec.ID = %q, want %q", MicrosoftSpec.ID, ProviderMicrosoft)
	}
	commonEP := microsoft.AzureADEndpoint("common")
	if MicrosoftSpec.Endpoints.OAuth2.AuthURL != commonEP.AuthURL ||
		MicrosoftSpec.Endpoints.OAuth2.TokenURL != commonEP.TokenURL {
		t.Fatalf("MicrosoftSpec endpoints mismatch: got %+v, want %+v",
			MicrosoftSpec.Endpoints.OAuth2, commonEP)
	}
	if MicrosoftSpec.Endpoints.ProfileURL == "" {
		t.Fatal("MicrosoftSpec.Endpoints.ProfileURL is empty")
	}

	p := NewMicrosoft("id", "secret")
	if p.ID() != ProviderMicrosoft {
		t.Fatalf("NewMicrosoft ID() = %q, want %q", p.ID(), ProviderMicrosoft)
	}

	conf := p.Config(&serviceConfig{
		BaseURL:              "https://app.example",
		CallbackPathTemplate: "/u/auth/{provider}/callback",
	})
	if conf.ClientID != "id" || conf.ClientSecret != "secret" {
		t.Fatalf("NewMicrosoft Config credentials = (%q,%q), want (%q,%q)", conf.ClientID, conf.ClientSecret, "id", "secret")
	}
	if conf.Endpoint.AuthURL != commonEP.AuthURL || conf.Endpoint.TokenURL != commonEP.TokenURL {
		t.Fatalf("NewMicrosoft Config.Endpoint mismatch: got %+v, want %+v", conf.Endpoint, commonEP)
	}
}

func TestMicrosoftWithTenant(t *testing.T) {
	t.Parallel()

	tenant := "organizations"
	p := NewMicrosoft("id", "secret", WithTenant(tenant))

	conf := p.Config(&serviceConfig{
		BaseURL:              "https://app.example",
		CallbackPathTemplate: "/u/auth/{provider}/callback",
	})

	wantEP := microsoft.AzureADEndpoint(tenant)
	if conf.Endpoint.AuthURL != wantEP.AuthURL || conf.Endpoint.TokenURL != wantEP.TokenURL {
		t.Fatalf("NewMicrosoft WithTenant Endpoint mismatch: got %+v, want %+v", conf.Endpoint, wantEP)
	}
}

func TestMicrosoftExtractProfile(t *testing.T) {
	t.Parallel()

	data := ProfileMap{
		"id":          "abc",
		"displayName": "John Smith",
		"givenName":   "John",
		"surname":     "Smith",
		"mail":        "john@example.com",
	}

	p, err := microsoftExtractProfile(data, nil)
	if err != nil {
		t.Fatalf("microsoftExtractProfile() error = %v, want nil", err)
	}
	if p.CanonicalID != "abc" {
		t.Fatalf("CanonicalID = %q, want %q", p.CanonicalID, "abc")
	}
	if p.Name != "John Smith" || p.FirstName != "John" || p.LastName != "Smith" {
		t.Fatalf("Name fields = %#v, want John / John / Smith", p)
	}
	if p.Email != "john@example.com" {
		t.Fatalf("Email = %q, want %q", p.Email, "john@example.com")
	}
	if p.ID == "" {
		t.Fatal("ID should not be empty")
	}
}
