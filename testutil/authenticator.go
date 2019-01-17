package testutil

import (
	"net/http"

	"go.jonnrb.io/webauth/types"
)

type FakeAuthenticator struct {
	User      types.User
	TargetURL string
	Error     error
}

func (f FakeAuthenticator) GetEUC(r *http.Request) (u types.User, targetURL string, err error) {
	return f.User, f.TargetURL, f.Error
}
