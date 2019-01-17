package testutil

import (
	"testing"

	"go.jonnrb.io/webauth/types"
)

func TestFakeTokenBox_Unseal(t *testing.T) {
	b := FakeTokenBox{
		User:  types.User{Email: "jane@example.test"},
		Token: "guest",
	}

	u, err := b.Unseal("guest")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	} else if u.Email != "jane@example.test" {
		t.Errorf("wrong email %q", u.Email)
	}
}

func TestFakeTokenBox_Unseal_wrongToken(t *testing.T) {
	b := FakeTokenBox{Token: "guest"}
	_, err := b.Unseal("wrong")
	if err == nil {
		t.Error("expected error")
	}
}

func TestFakeTokenBox_Unseal_expired(t *testing.T) {
	b := FakeTokenBox{Token: "expired"}
	_, err := b.Unseal("guest")
	if err != types.ErrTokenExpired {
		t.Errorf("expected types.ErrTokenExpired; got: %v", err)
	}
}
