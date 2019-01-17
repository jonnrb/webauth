package testutil

import (
	"testing"

	"go.jonnrb.io/webauth/types"
)

type FakeAuthorizer types.User

func (a FakeAuthorizer) IsAuthorized(u types.User) bool {
	return u == types.User(a)
}

type ErrorAuthorizer struct {
	*testing.T
}

func (a ErrorAuthorizer) IsAuthorized(u types.User) bool {
	a.Errorf("unexpected IsAuthorized call with user %v", u)
	return false
}
