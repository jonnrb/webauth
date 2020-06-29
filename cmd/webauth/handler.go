package main

import (
	"net/http"

	"go.jonnrb.io/webauth/authn"
	"go.jonnrb.io/webauth/errors"
	"go.jonnrb.io/webauth/types"
)

type Handler struct {
	EUCBox        types.EUCBox
	Authenticator types.Authenticator
	Login         types.Login
	Authorizer    types.Authorizer
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, targetURL, err := h.getEUC(w, r)

	// If the user has no credentials, request they log in. Otherwise, an error
	// is the end of the road.
	if err == authn.ErrNoCredentials {
		h.Login.RequestCredentials(w, r)
		return
	} else if err != nil {
		errors.WriteError(w, err)
		return
	}

	// Just write unauthorized if the user is not authorized. This could get
	// fancier but there's no need right now.
	if !h.Authorizer.IsAuthorized(u) {
		errors.New(http.StatusForbidden, "forbidden", nil).WriteHTTP(w)
	}

	h.handleAuthorized(w, r, u, targetURL)
}

func (h *Handler) getEUC(w http.ResponseWriter, r *http.Request) (u types.User, targetURL string, err error) {
	u, targetURL, err = h.Authenticator.GetEUC(r)

	switch err {
	case authn.ErrNoCredentials:
		u, targetURL, err = h.EUCBox.GetEUC(r)
	case authn.ErrBadCallbackState:
		var eucBoxErr error
		u, targetURL, eucBoxErr = h.EUCBox.GetEUC(r)
		if alreadyHasEUC := eucBoxErr == nil; alreadyHasEUC {
			err = nil
		}
	case nil:
		// Only give a EUC token if the authenticator has a EUC (i.e. don't give
		// a EUC if the EUCBox already contains a EUC).
		h.EUCBox.GiveEUC(w, u)
	}

	return
}

func (h *Handler) handleAuthorized(w http.ResponseWriter, r *http.Request, u types.User, targetURL string) {
	if targetURL == "" {
		w.Header().Set("X-Forwarded-User", u.Email)
		w.WriteHeader(http.StatusOK)
	} else {
		http.Redirect(w, r, targetURL, http.StatusFound)
	}
}
