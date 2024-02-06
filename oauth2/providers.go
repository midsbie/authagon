package oauth2

import (
	"github.com/midsbie/authagon/secutil"
	"golang.org/x/oauth2/google"
)

func NewGoogle() *ProviderBlueprint {
	const name = "google"
	return &ProviderBlueprint{
		name: name,
		endpoint: endpoint{
			Endpoint:   google.Endpoint,
			ProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
		},
		scopes: []string{"email", "https://www.googleapis.com/auth/userinfo.profile"},
		mapProfile: func(data ParsedProfile, _ []byte) (Profile, error) {
			id, err := secutil.HashID(name + "_" + data.String("sub"))
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
		},
	}
}
