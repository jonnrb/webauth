package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.jonnrb.io/webauth/cookie"
	"go.jonnrb.io/webauth/testutil"
	"go.jonnrb.io/webauth/types"
)

func TestOauthAuthenticator_GetEUC(t *testing.T) {
	cfg := testutil.FakeOauthConfig{
		User: types.User{Email: "jane@example.test"},
	}
	a := OauthAuthenticator{
		Backend:          &cfg,
		CSRFCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
	}
	r := httptest.NewRequest("get", "https://auth.example.test/?code=foo&state=nonce:https://example.test/target", nil)
	r.AddCookie(&http.Cookie{Name: "chocolate_chip", Value: "nonce"})

	u, targetURL, err := a.GetEUC(r)

	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "jane@example.test" {
		t.Error("wrong email")
	}
	if targetURL != "https://example.test/target" {
		t.Error("wrong targetURL")
	}
}

func TestOauthAuthenticator_GetEUC_notInCallback(t *testing.T) {
	a := OauthAuthenticator{
		CSRFCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
	}
	r := httptest.NewRequest("get", "https://example.test/", nil)

	_, _, err := a.GetEUC(r)

	if err != ErrNoCredentials {
		t.Fatal(err)
	}
}

func TestOauthAuthenticator_GetEUC_noCSRFToken(t *testing.T) {
	a := OauthAuthenticator{
		CSRFCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
	}
	r := httptest.NewRequest("get", "https://auth.example.test/?code=foo&state=nonce:https://example.test/target", nil)

	_, _, err := a.GetEUC(r)

	if err != ErrNoCredentials {
		t.Fatal(err)
	}
}

func TestOauthAuthenticator_GetEUC_badStatePair(t *testing.T) {
	a := OauthAuthenticator{
		CSRFCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
	}
	r := httptest.NewRequest("get", "https://auth.example.test/?code=foo&state=badstatepair", nil)
	r.AddCookie(&http.Cookie{Name: "chocolate_chip", Value: "nonce"})

	_, _, err := a.GetEUC(r)

	if err == nil {
		t.Error("missing a CSRF token should be an error")
	} else if err == ErrNoCredentials {
		t.Error("missing a CSRF token should be an error different from ErrNoCredentials")
	}
}

func TestOauthAuthenticator_GetEUC_wrongNonce(t *testing.T) {
	a := OauthAuthenticator{
		CSRFCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
	}
	r := httptest.NewRequest("get", "https://auth.example.test/?code=foo&state=nonce:https://example.test/target", nil)
	r.AddCookie(&http.Cookie{Name: "chocolate_chip", Value: "wrongvalue"})

	_, _, err := a.GetEUC(r)

	if err == nil {
		t.Error("missing a CSRF token should be an error")
	} else if err == ErrNoCredentials {
		t.Error("missing a CSRF token should be an error different from ErrNoCredentials")
	}
}

func TestOauthAuthenticator_RequestCredentials(t *testing.T) {
	cfg := testutil.FakeOauthConfig{
		DummyAuthCodeURL: "https://auth.test/",
	}
	a := OauthAuthenticator{
		Backend:          &cfg,
		CSRFCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
		Nonce: func() (string, error) {
			return "nonce", nil
		},
	}
	r := httptest.NewRequest("get", "https://example.test/foo", nil)
	r.Header.Set("X-Forwarded-Host", "example.test")
	var w httptest.ResponseRecorder

	a.RequestCredentials(&w, r)

	res := w.Result()
	checkCookie(t, res, "nonce")
	if res.StatusCode != http.StatusFound {
		t.Error("expected redirect status code")
	}
	if res.Header.Get("Location") != "https://auth.test/nonce:https://example.test/foo" {
		t.Error("incorrect redirect URL")
	}
}
