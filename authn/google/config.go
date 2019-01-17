package google

import (
	"context"
	"encoding/json"

	"go.jonnrb.io/webauth/types"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	*oauth2.Config
}

func New(clientID, clientSecret, redirectURL string) *Config {
	return &Config{
		Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/userinfo.email",
			},
			Endpoint: google.Endpoint,
		},
	}
}

type googleUser struct {
	Email string `json:"email"`
}

func (c *Config) GetUser(ctx context.Context, token *oauth2.Token) (u types.User, err error) {
	cli := c.Client(ctx, token)

	res, err := cli.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return
	}
	defer res.Body.Close()

	var gu googleUser
	err = json.NewDecoder(res.Body).Decode(&gu)
	if err != nil {
		return
	}

	u.Email = gu.Email
	return
}
