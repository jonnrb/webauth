package testutil

import (
	"testing"

	"go.jonnrb.io/webauth/types"
)

func TestFakeAuthorizer_IsAuthorized(t *testing.T) {
	a := FakeAuthorizer{Email: "jane@example.test"}

	if !a.IsAuthorized(types.User{Email: "jane@example.test"}) {
		t.Errorf("jane@example.test should be authorized")
	}
	if a.IsAuthorized(types.User{Email: "bob@example.test"}) {
		t.Errorf("bob@example.test should not be authorized")
	}
}
