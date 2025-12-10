package oauth2

import (
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

// Built-in provider IDs.
const (
	ProviderGoogle    ProviderID = "google"
	ProviderMicrosoft ProviderID = "microsoft"
)

// GoogleSpec describes the Google OAuth2 provider at the protocol
// level: endpoints, default scopes, and profile extraction.
var GoogleSpec = ProviderSpec{
	ID: ProviderGoogle,
	Endpoints: ProviderEndpoints{
		OAuth2:     google.Endpoint,
		ProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
	},
	DefaultScopes: []string{
		"email",
		"https://www.googleapis.com/auth/userinfo.profile",
	},
	ExtractProfile: googleExtractProfile,
}

// MicrosoftSpec describes the Microsoft OAuth2 provider at the protocol
// level: endpoints, default scopes, and profile extraction. It uses the
// "common" multi-tenant endpoint by default.
var MicrosoftSpec = ProviderSpec{
	ID: ProviderMicrosoft,
	Endpoints: ProviderEndpoints{
		OAuth2:     microsoft.AzureADEndpoint("common"),
		ProfileURL: "https://graph.microsoft.com/v1.0/me",
	},
	DefaultScopes:  []string{"User.Read"},
	ExtractProfile: microsoftExtractProfile,
}

// NewGoogle constructs a Provider for Google using the given client
// credentials and optional ProviderOptions.
func NewGoogle(clientID, clientSecret string, opts ...ProviderOption) Provider {
	cfg := ProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	return NewProvider(GoogleSpec, cfg, opts...)
}

// MicrosoftOption customizes a Microsoft provider instance by adjusting
// its spec and configuration prior to construction.
type MicrosoftOption func(*ProviderSpec, *ProviderConfig)

// WithTenant configures the Microsoft provider to use a specific Azure
// AD tenant for its OAuth2 endpoints instead of the default "common"
// endpoint.
func WithTenant(tenant string) MicrosoftOption {
	return func(spec *ProviderSpec, _ *ProviderConfig) {
		spec.Endpoints.OAuth2 = microsoft.AzureADEndpoint(tenant)
	}
}

// WithMicrosoftScopes overrides the default scopes for a Microsoft
// provider instance.
func WithMicrosoftScopes(scopes ...string) MicrosoftOption {
	return func(_ *ProviderSpec, cfg *ProviderConfig) {
		WithScopes(scopes...)(cfg)
	}
}

// WithMicrosoftCallbackURL overrides the callback URL for a Microsoft
// provider instance.
func WithMicrosoftCallbackURL(callbackURL string) MicrosoftOption {
	return func(_ *ProviderSpec, cfg *ProviderConfig) {
		WithCallbackURL(callbackURL)(cfg)
	}
}

// NewMicrosoft constructs a Provider for Microsoft using the given
// client credentials and optional MicrosoftOptions.
func NewMicrosoft(clientID, clientSecret string, opts ...MicrosoftOption) Provider {
	spec := MicrosoftSpec
	cfg := ProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	for _, opt := range opts {
		opt(&spec, &cfg)
	}
	return NewProvider(spec, cfg)
}

func googleExtractProfile(data ProfileMap, _ []byte) (Profile, error) {
	canonicalID := data.String("sub")
	id, err := HashID(string(ProviderGoogle) + "_" + canonicalID)
	if err != nil {
		return Profile{}, err
	}

	return Profile{
		ID:          id,
		CanonicalID: canonicalID,
		Name:        data.String("name"),
		FirstName:   data.String("given_name"),
		LastName:    data.String("family_name"),
		Email:       data.String("email"),
		PictureURL:  data.String("picture"),
		Attributes:  data,
	}, nil
}

func microsoftExtractProfile(data ProfileMap, _ []byte) (Profile, error) {
	canonicalID := data.String("id")
	id, err := HashID(string(ProviderMicrosoft) + "_" + canonicalID)
	if err != nil {
		return Profile{}, err
	}

	return Profile{
		ID:          id,
		CanonicalID: canonicalID,
		Name:        data.String("displayName"),
		FirstName:   data.String("givenName"),
		LastName:    data.String("surname"),
		Email:       data.String("mail"),
		Attributes:  data,
	}, nil
}
