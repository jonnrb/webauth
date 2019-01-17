package types

import (
	"net/http"
)

type User struct {
	Email string
}

type TokenBox interface {
	Seal(u User) (token string, err error)
	Unseal(token string) (u User, err error)
}

// Interface for a specific browser cookie.
type CookieRecipe interface {
	// "Giving" a client the empty string should unset the cookie.
	Give(w http.ResponseWriter, value string)

	Get(r *http.Request) (value string, ok bool)
}

type Authorizer interface {
	IsAuthorized(u User) bool
}

type Authenticator interface {
	GetEUC(r *http.Request) (u User, targetURL string, err error)
}

type EUCBox interface {
	Authenticator
	GiveEUC(w http.ResponseWriter, u User) error
}

type Login interface {
	RequestCredentials(w http.ResponseWriter, r *http.Request)
}
