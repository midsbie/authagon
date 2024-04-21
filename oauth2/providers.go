package oauth2

import (
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

var (
	_ Provider         = (*googleProvider)(nil)
	_ Provider         = (*microsoftProvider)(nil)
	_ ProfileExtractor = (*googleProvider)(nil)
	_ ProfileExtractor = (*microsoftProvider)(nil)
)

type googleProvider struct {
	StandardProvider
}

func NewGoogle(clientID, clientSecret string, options ...StandardProviderOption) *googleProvider {
	p := &googleProvider{
		StandardProvider{
			name: "google",
			endpoints: endpoints{
				OAuth2:     google.Endpoint,
				ProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
			},
			scopes: []string{"email", "https://www.googleapis.com/auth/userinfo.profile"},
			config: NewProviderConfig(clientID, clientSecret, options),
		},
	}
	p.mapper = p
	return p
}

func (p *googleProvider) ExtractProfile(data ProfileMap, _ []byte) (Profile, error) {
	canonicalId := data.String("sub")
	id, err := HashID(p.name + "_" + canonicalId)
	if err != nil {
		return Profile{}, err
	}

	return Profile{
		ID:          id,
		CanonicalID: canonicalId,
		Name:        data.String("name"),
		FirstName:   data.String("given_name"),
		LastName:    data.String("family_name"),
		Email:       data.String("email"),
		PictureURL:  data.String("picture"),
		Attributes:  data,
	}, nil
}

type microsoftProvider struct {
	StandardProvider
}

func NewMicrosoft(clientID, clientSecret string, options ...StandardProviderOption) *microsoftProvider {
	p := &microsoftProvider{
		StandardProvider{
			name: "microsoft",
			endpoints: endpoints{
				OAuth2:     microsoft.AzureADEndpoint("common"),
				ProfileURL: "https://graph.microsoft.com/v1.0/me",
			},
			scopes: []string{"User.Read"},
			config: NewProviderConfig(clientID, clientSecret, options),
		},
	}
	p.mapper = p
	return p
}

func (p *microsoftProvider) ExtractProfile(data ProfileMap, _ []byte) (Profile, error) {
	canonicalId := data.String("id")
	id, err := HashID(p.name + "_" + canonicalId)
	if err != nil {
		return Profile{}, err
	}

	return Profile{
		ID:          id,
		CanonicalID: canonicalId,
		Name:        data.String("displayName"),
		FirstName:   data.String("givenName"),
		LastName:    data.String("surname"),
		Email:       data.String("mail"),
		Attributes:  data,
	}, nil
}
