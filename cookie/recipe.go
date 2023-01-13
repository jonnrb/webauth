package cookie

import (
	"net/http"
	"time"
)

type EphemeralRecipe struct {
	Name           string
	Domain         string
	Duration       time.Duration
	AllowRedirects bool
}

func (r *EphemeralRecipe) Give(w http.ResponseWriter, value string) {
	var expires time.Time
	if r.Duration == time.Duration(0) {
		expires = time.Now().Add(-1 * time.Hour)
	} else {
		expires = time.Now().Add(r.Duration)
	}

	var sameSite http.SameSite
	if r.AllowRedirects {
		sameSite = http.SameSiteLaxMode
	} else {
		sameSite = http.SameSiteStrictMode
	}

	http.SetCookie(w, &http.Cookie{
		Name:     r.Name,
		Value:    value,
		Domain:   r.Domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: sameSite,
		Expires:  expires,
	})
}

func (r *EphemeralRecipe) Get(req *http.Request) (value string, ok bool) {
	c, err := req.Cookie(r.Name)
	if c == nil || err != nil {
		return
	}
	return c.Value, true
}
