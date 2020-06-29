package authn

import (
	"context"
	"net/http"
	"time"

	"go.jonnrb.io/webauth/errors"
	"go.jonnrb.io/webauth/types"
	"golang.org/x/oauth2"
)

type OauthAuthenticator struct {
	Backend          OauthConfig
	CSRFCookieRecipe types.CookieRecipe
	Nonce            func() (string, error)
}

type OauthConfig interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	GetUser(ctx context.Context, token *oauth2.Token) (types.User, error)
}

var (
	ErrNoCredentials    = errors.New(http.StatusUnauthorized, "no credentials", nil)
	ErrBadCallbackState = errors.New(http.StatusBadRequest, "invalid callback state", nil)
)

var errBadRequest = errors.New(http.StatusBadRequest, "bad request", nil)

// Gets credentials from an oauth2 callback.
func (a *OauthAuthenticator) GetEUC(r *http.Request) (u types.User, targetURL string, err error) {
	var ok bool
	ok, err = a.inCallback(r)
	if !ok {
		return
	}

	targetURL, err = a.extractAndVerifyTargetURL(r)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	token, err := a.Backend.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		err = errors.New(http.StatusInternalServerError, "could not authenticate", err)
		return
	}

	u, err = a.Backend.GetUser(ctx, token)
	return
}

// Requests the user log in via oauth2.
func (a *OauthAuthenticator) RequestCredentials(w http.ResponseWriter, r *http.Request) {
	targetURL := extractTargetURL(r)

	// Attach a CSRF cookie to the response. The value used is also passed
	// along in the Oauth state so it can be checked in the callback. If the
	// callback state and the cookie agree, the Oauth flow must have been
	// initiated from somewhere that can set cookies on the cookie domain.
	n, err := a.Nonce()
	if err != nil {
		errors.WriteError(w, err)
		return
	}
	a.CSRFCookieRecipe.Give(w, n)

	// Redirect the user's browser to the auth code URL, where the state
	// parameter contains the CSRF nonce and the redirect URL.
	http.Redirect(w, r, a.Backend.AuthCodeURL(n+":"+targetURL), http.StatusFound)
}
