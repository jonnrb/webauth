package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.jonnrb.io/webauth/cookie"
	"go.jonnrb.io/webauth/testutil"
	"go.jonnrb.io/webauth/types"
)

func checkCookie(t *testing.T, res *http.Response, value string) {
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Error("expected exactly one cookie set")
		return
	}
	c := cookies[0]
	if c.Value != value {
		t.Errorf("expected token %q got %q", value, c.Value)
	}
}

func TestCookieAuthenticator_GetEUC(t *testing.T) {
	tb := testutil.FakeTokenBox{
		User:  types.User{Email: "jane@example.test"},
		Token: "guest",
	}
	a := CookieAuthenticator{
		AuthCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
		TokenBox:         &tb,
	}
	r := httptest.NewRequest("get", "https://example.test/", nil)
	r.AddCookie(&http.Cookie{Name: "chocolate_chip", Value: "guest"})

	u, targetURL, err := a.GetEUC(r)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "jane@example.test" {
		t.Error("got wrong email")
	}
	if targetURL != "" {
		t.Error("should have empty targetURL")
	}
}

func TestCookieAuthenticator_GetEUC_noCookie(t *testing.T) {
	tb := testutil.FakeTokenBox{
		User:  types.User{Email: "jane@example.test"},
		Token: "guest",
	}
	a := CookieAuthenticator{
		AuthCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
		TokenBox:         &tb,
	}
	var w httptest.ResponseRecorder

	err := a.GiveEUC(&w, types.User{Email: "jane@example.test"})

	if err != nil {
		t.Fatal(err)
	}
	checkCookie(t, w.Result(), "guest")
}

func TestCookieAuthenticator_GetEUC_expiredToken(t *testing.T) {
	tb := testutil.FakeTokenBox{
		User:  types.User{Email: "jane@example.test"},
		Token: "expired",
	}
	a := CookieAuthenticator{
		AuthCookieRecipe: &cookie.EphemeralRecipe{Name: "chocolate_chip"},
		TokenBox:         &tb,
	}
	r := httptest.NewRequest("get", "https://example.test/", nil)
	r.AddCookie(&http.Cookie{Name: "chocolate_chip", Value: "guest"})

	_, _, err := a.GetEUC(r)
	if err != ErrNoCredentials {
		t.Errorf("err should be ErrNoCredentials got: %v", err)
	}
}
