package testutil

import (
	"testing"

	"go.jonnrb.io/webauth/types"
)

func TestFakeAuthenticator_GetEUC(t *testing.T) {
	a := FakeAuthenticator{
		User:      types.User{Email: "jane@example.test"},
		TargetURL: "https://example.test/",
	}

	u, targetURL, err := a.GetEUC(nil)
	if u != (types.User{Email: "jane@example.test"}) {
		t.Errorf("unexpected user %v", u)
	}
	if targetURL != "https://example.test/" {
		t.Errorf("unexpected targetURL %q", targetURL)
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
