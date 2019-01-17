package testutil

import (
	"fmt"

	"go.jonnrb.io/webauth/types"
)

type FakeTokenBox struct {
	User  types.User
	Token string
}

func (b *FakeTokenBox) Seal(u types.User) (token string, err error) {
	token = b.Token
	return
}

func (b *FakeTokenBox) Unseal(token string) (u types.User, err error) {
	if b.Token == "expired" {
		err = types.ErrTokenExpired
	} else if token == b.Token {
		u = b.User
	} else {
		err = fmt.Errorf("wrong token")
	}
	return
}
