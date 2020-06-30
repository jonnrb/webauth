package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.jonnrb.io/webauth/authn"
	"go.jonnrb.io/webauth/cookie"
	"go.jonnrb.io/webauth/testutil"
	"go.jonnrb.io/webauth/types"
)

func newTestingEUCBox() types.EUCBox {
	return &authn.CookieAuthenticator{
		AuthCookieRecipe: &cookie.EphemeralRecipe{
			Name: "chocolate_chip",
		},
		TokenBox: &testutil.FakeTokenBox{
			User:  types.User{Email: "jane@example.test"},
			Token: "guest",
		},
	}
}

func TestHandler_ServeHTTP_noCredentials(t *testing.T) {
	var l testutil.CounterLogin
	h := Handler{
		EUCBox:        newTestingEUCBox(),
		Authenticator: &testutil.FakeAuthenticator{Error: authn.ErrNoCredentials},
		Login:         &l,
		Authorizer:    testutil.ErrorAuthorizer{t},
	}
	r := httptest.NewRequest("get", "https://example.test/foo", nil)
	var w httptest.ResponseRecorder

	h.ServeHTTP(&w, r)

	if l != 1 {
		t.Errorf("expected exactly one RequestCredentials call; got %d calls", l)
	}
}

func TestHandler_ServeHTTP_hasAuthenticatorCredentials(t *testing.T) {
	h := Handler{
		EUCBox: newTestingEUCBox(),
		Authenticator: &testutil.FakeAuthenticator{
			User:      types.User{Email: "jane@example.test"},
			TargetURL: "https://site.example.test/some-page",
		},
		Login:      testutil.ErrorLogin{t},
		Authorizer: testutil.FakeAuthorizer{Email: "jane@example.test"},
	}
	r := httptest.NewRequest("get", "https://auth.example.test/", nil)
	w := httptest.ResponseRecorder{Body: &bytes.Buffer{}}

	h.ServeHTTP(&w, r)

	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("unexpected response status %q", res.Status)
	}
	body := mustReadAll(res.Body)
	expectedBody := `<!doctype html>
<html lang="en"><meta charset="utf-8">
<title>Logged in</title>
<script>window.location.href = "https:\/\/site.example.test\/some-page";</script>
<h1>Logged in</h1>
<p>Continue to <a href="https://site.example.test/some-page">https://site.example.test/some-page</a>.
`
	if body != expectedBody {
		t.Errorf("body did not match; got %q, want %q", body, expectedBody)
	}
	if cookies := res.Cookies(); len(cookies) != 1 {
		t.Errorf("expected one cookie; got %v", cookies)
	} else {
		c := cookies[0]
		if c.Name != "chocolate_chip" {
			t.Errorf("unexpected cookie name %q", c.Name)
		}
		if c.Value != "guest" {
			t.Errorf("unexpected token %q", c.Value)
		}
	}
}

func mustReadAll(r io.Reader) string {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestHandler_ServeHTTP_hasAuthCookie(t *testing.T) {
	h := Handler{
		EUCBox:        newTestingEUCBox(),
		Authenticator: &testutil.FakeAuthenticator{Error: authn.ErrNoCredentials},
		Login:         testutil.ErrorLogin{t},
		Authorizer:    testutil.FakeAuthorizer{Email: "jane@example.test"},
	}
	r := httptest.NewRequest("get", "https://example.test/", nil)
	r.AddCookie(&http.Cookie{Name: "chocolate_chip", Value: "guest"})
	var w httptest.ResponseRecorder

	h.ServeHTTP(&w, r)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("unexpected response status %q", res.Status)
	}
}

func TestHandler_ServeHTTP_unauthorized(t *testing.T) {
	h := Handler{
		EUCBox:        newTestingEUCBox(),
		Authenticator: &testutil.FakeAuthenticator{Error: authn.ErrNoCredentials},
		Login:         testutil.ErrorLogin{t},
		Authorizer:    testutil.FakeAuthorizer{Email: "bob@example.test"},
	}
	r := httptest.NewRequest("get", "https://example.test/", nil)
	r.AddCookie(&http.Cookie{Name: "chocolate_chip", Value: "guest"})
	var w httptest.ResponseRecorder

	h.ServeHTTP(&w, r)

	res := w.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("unexpected response status %q", res.Status)
	}
}
