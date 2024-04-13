package oauth2

import (
	"golang.org/x/oauth2/google"
)

var (
	_ Provider      = (*googleProvider)(nil)
	_ ProfileMapper = (*googleProvider)(nil)
)

type googleProvider struct {
	StandardProvider
}

func NewGoogle(clientID, clientSecret string, options ...StandardProviderOption) *googleProvider {
	p := &googleProvider{
		StandardProvider{
			name: "google",
			endpoint: endpoint{
				Endpoint:   google.Endpoint,
				ProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
			},
			scopes: []string{"email", "https://www.googleapis.com/auth/userinfo.profile"},
			config: NewProviderConfig(clientID, clientSecret, options),
		},
	}
	p.mapper = p
	return p
}

func (p *googleProvider) MapProfile(data ParsedProfile, _ []byte) (Profile, error) {
	id, err := HashID(p.name + "_" + data.String("sub"))
	if err != nil {
		return Profile{}, err
	}

	return Profile{
		ID:          id,
		CanonicalID: data.String("sub"),
		Name:        data.String("name"),
		FirstName:   data.String("given_name"),
		LastName:    data.String("family_name"),
		Email:       data.String("email"),
		PictureURL:  data.String("picture"),
	}, nil
}
