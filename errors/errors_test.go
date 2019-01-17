package errors

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func readAllOrFail(t *testing.T, r io.Reader) string {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatalf("fatal error reading: %v", err)
		return ""
	}
	return string(b)
}

func ExampleWithCause_wrappingAnyError() {
	cause := fmt.Errorf("foo")

	fmt.Println(WithCause("bar", cause))

	// Output: HTTP error: bar: foo
}

func ExampleWithCause_wrappingHTTPError() {
	cause := New(http.StatusForbidden, "forbidden", nil)
	fmt.Println(WithCause("bar", cause))

	cause.Inner = fmt.Errorf("foo")
	fmt.Println(WithCause("bar", cause))

	cause = HTTPError{Inner: fmt.Errorf("foo")}
	fmt.Println(WithCause("bar", cause))

	// Output:
	// HTTP 403 "forbidden": bar
	// HTTP 403 "forbidden": bar: foo
	// HTTP error: bar: foo
}

func TestWriteError_writingAnyError(t *testing.T) {
	w := httptest.NewRecorder()

	WriteError(w, fmt.Errorf("foo"))

	res := w.Result()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("unexpected error code %d", res.StatusCode)
	}
	if s := readAllOrFail(t, res.Body); s != "internal error\n" {
		t.Errorf("unexpected response body %q", s)
	}
}

func TestWriteError_writingHTTPError(t *testing.T) {
	w := httptest.NewRecorder()

	WriteError(w, New(http.StatusForbidden, "forbidden", fmt.Errorf("logged but not sent to client")))

	res := w.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("unexpected error code %d", res.StatusCode)
	}
	if s := readAllOrFail(t, res.Body); s != "forbidden\n" {
		t.Errorf("unexpected response body %q", s)
	}
}

func ExampleWriteError_writingAnyError() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	WriteError(&httptest.ResponseRecorder{}, fmt.Errorf("foo"))

	// Output:
	// HTTP error: foo
}

func ExampleWriteError_writingHTTPError() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	WriteError(
		&httptest.ResponseRecorder{},
		New(http.StatusForbidden, "forbidden", fmt.Errorf("logged but not sent to client")))

	// Output:
	// HTTP 403 "forbidden": logged but not sent to client
}
