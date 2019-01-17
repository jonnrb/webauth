package authn

import (
	"fmt"
	"net/http"
	"strings"

	"go.jonnrb.io/webauth/errors"
)

func inCallback(r *http.Request) bool {
	return r.URL.Query().Get("state") != "" && r.URL.Query().Get("code") != ""
}

func (a *OauthAuthenticator) extractAndVerifyTargetURL(r *http.Request) (string, error) {
	csrf, ok := a.CSRFCookieRecipe.Get(r)
	if !ok {
		return "", errors.WithCause("no csrf cookie", errBadRequest)
	}

	state := r.URL.Query().Get("state")
	statePair := strings.SplitN(state, ":", 2)
	if len(statePair) != 2 {
		return "", errors.WithCause(fmt.Sprintf("bad state param: %q", state), errBadRequest)
	}

	nonce := statePair[0]
	if nonce != csrf {
		return "", errors.WithCause(fmt.Sprintf("bad nonce in state: nonce=%q csrf=%q", nonce, csrf), errBadRequest)
	}

	return statePair[1], nil
}

func extractTargetURL(r *http.Request) string {
	u := *r.URL

	// Always use HTTPS. The rest of the server assumes HTTPS is used.
	u.Scheme = "https"

	// This header will be correct when requests come from traefik.
	u.Host = r.Header.Get("X-Forwarded-Host")

	return u.String()
}
