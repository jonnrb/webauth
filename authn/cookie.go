package authn

import (
	"net/http"

	"go.jonnrb.io/webauth/types"
)

type CookieAuthenticator struct {
	AuthCookieRecipe types.CookieRecipe
	TokenBox         types.TokenBox
}

// Gets and authenticates a EUC embedded in a cookie.
func (a *CookieAuthenticator) GetEUC(r *http.Request) (u types.User, targetURL string, err error) {
	token, ok := a.AuthCookieRecipe.Get(r)
	if !ok {
		err = ErrNoCredentials
		return
	}

	u, err = a.TokenBox.Unseal(token)
	if err == types.ErrTokenExpired {
		err = ErrNoCredentials
	}

	// There is no targetURL. If the user authenticates with a cookie, they
	// should stay put on this URL. (Traefik makes requests to the real service
	// when a 200 is returned.)
	return
}

// Embeds a EUC in a cookie sent to the client. This should be done before
// w.WriteHeader().
func (a *CookieAuthenticator) GiveEUC(w http.ResponseWriter, u types.User) error {
	token, err := a.TokenBox.Seal(u)
	if err != nil {
		return err
	}
	a.AuthCookieRecipe.Give(w, token)
	return nil
}
