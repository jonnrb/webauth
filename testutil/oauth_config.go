package testutil

import (
	"context"

	"go.jonnrb.io/webauth/types"
	"golang.org/x/oauth2"
)

type FakeOauthConfig struct {
	DummyAuthCodeURL string
	User             types.User
}

func (c *FakeOauthConfig) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.DummyAuthCodeURL + state
}

func (c *FakeOauthConfig) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}

func (c *FakeOauthConfig) GetUser(ctx context.Context, token *oauth2.Token) (u types.User, err error) {
	u = c.User
	return
}
