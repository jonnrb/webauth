package authz

import (
	"testing"

	"go.jonnrb.io/webauth/types"
)

func TestEmailList(t *testing.T) {
	a := NewEmailList([]string{"jane@domain.test"})

	if a.IsAuthorized(types.User{Email: "bob@domain.test"}) {
		t.Error("bob is not on the list and should not be authorized")
	}
	if !a.IsAuthorized(types.User{Email: "jane@domain.test"}) {
		t.Error("jane is on the list and should be authorized")
	}
}
