package cookie

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeRoundTripper func(w http.ResponseWriter, r *http.Request)

func (h fakeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		defer r.Body.Close()
	}
	var w httptest.ResponseRecorder
	h(&w, r)
	return w.Result(), nil
}

func newClientAttachedTo(h func(w http.ResponseWriter, r *http.Request)) (c http.Client) {
	c.Transport = fakeRoundTripper(h)
	return
}

func newCookieJar() http.CookieJar {
	j, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return j
}

func roundtripGiveIntoJar(j http.CookieJar, recipe *EphemeralRecipe, url, value string) {
	cli := newClientAttachedTo(func(w http.ResponseWriter, r *http.Request) {
		recipe.Give(w, value)
	})
	cli.Jar = j
	_, err := cli.Get(url)
	if err != nil {
		panic(err)
	}
}

func roundtripGetFromJar(j http.CookieJar, recipe *EphemeralRecipe, url string) (value string, ok bool) {
	cli := newClientAttachedTo(func(w http.ResponseWriter, r *http.Request) {
		value, ok = recipe.Get(r)
	})
	cli.Jar = j
	_, err := cli.Get(url)
	if err != nil {
		panic(err)
	}
	return
}

func TestEphemeralCookie_Give(t *testing.T) {
	recipe := EphemeralRecipe{
		Name:     "chocolate_chip",
		Duration: 1 * time.Hour,
	}
	foo := "foo"

	var w httptest.ResponseRecorder
	recipe.Give(&w, foo)
	res := w.Result()

	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatal("expected one set cookie in the response")
	}

	c := cookies[0]
	if c.Name != recipe.Name {
		t.Errorf("expected cookie with name %q got %q", recipe.Name, c.Name)
	}
	if c.Value != foo {
		t.Errorf("expected cookie with value %q got %q", foo, c.Value)
	}
}

func TestEphemeralCookie_Get(t *testing.T) {
	recipe := EphemeralRecipe{
		Name:     "chocolate_chip",
		Duration: 1 * time.Hour,
	}
	foo := "foo"

	r := httptest.NewRequest("get", "https://example.test/", nil)
	r.AddCookie(&http.Cookie{Name: recipe.Name, Value: foo})

	v, ok := recipe.Get(r)
	if !ok {
		t.Error("cookie could not be retrieved")
	} else if v != foo {
		t.Errorf("expected value %q got %q", foo, v)
	}
}

func TestEphemeralCookie_roundtrip(t *testing.T) {
	recipe := EphemeralRecipe{
		Name:     "chocolate_chip",
		Duration: 1 * time.Hour,
	}
	expected := "foo"
	j := newCookieJar()

	roundtripGiveIntoJar(j, &recipe, "https://example.test/", expected)

	actual, ok := roundtripGetFromJar(j, &recipe, "https://example.test/")
	if !ok {
		t.Error("cookie not set")
	} else if actual != expected {
		t.Errorf("expected %q got %q", expected, actual)
	}
}

func TestEphemeralCookie_roundtripDomainCookie(t *testing.T) {
	recipe := EphemeralRecipe{
		Name:     "chocolate_chip",
		Domain:   "example.test",
		Duration: 1 * time.Hour,
	}
	expected := "foo"
	j := newCookieJar()

	roundtripGiveIntoJar(j, &recipe, "https://bakery.example.test/", expected)

	actual, ok := roundtripGetFromJar(j, &recipe, "https://home.example.test/")
	if !ok {
		t.Error("cookie not set")
	} else if actual != expected {
		t.Errorf("expected %q got %q", expected, actual)
	}
}

func TestEphemeralCookie_roundtripDomainCookieNoLeak(t *testing.T) {
	recipe := EphemeralRecipe{
		Name:     "chocolate_chip",
		Domain:   "example.test",
		Duration: 1 * time.Hour,
	}
	expected := "foo"

	// This cookie jar doesn't have a PSL, but IRL a PSL will be used.
	j := newCookieJar()

	roundtripGiveIntoJar(j, &recipe, "https://bakery.example.test/", expected)

	_, ok := roundtripGetFromJar(j, &recipe, "https://foo.test/")
	if ok {
		t.Error("cookie leaked across domain")
	}
}

func TestEphemeralCookie_roundtripGiveEmptyStringClearsCookie(t *testing.T) {
	recipe := EphemeralRecipe{
		Name:     "chocolate_chip",
		Duration: 1 * time.Hour,
	}
	j := newCookieJar()

	roundtripGiveIntoJar(j, &recipe, "https://example.test/", "i should go away on the next line")
	roundtripGiveIntoJar(j, &recipe, "https://example.test/", "")

	_, ok := roundtripGetFromJar(j, &recipe, "https://example.test/")
	if ok {
		t.Error("cookie was not cleared")
	}
}
