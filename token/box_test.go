package token

import (
	"testing"
	"time"

	"go.jonnrb.io/webauth/types"
)

func TestBox_Seal(t *testing.T) {
	b := Box{
		Duration: 1 * time.Hour,
		AEAD:     newAEAD(),
	}
	e := "jane@example.test"

	token, err := b.Seal(types.User{Email: e})

	if err != nil {
		t.Fatal(err)
	}
	pt, err := unseal(b.AEAD, token)
	if err != nil {
		t.Fatal(err)
	}
	u, err := decodeToken(pt)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != e {
		t.Errorf("expected email %q got %q", e, u.Email)
	}
}

func TestBox_Seal_cookieIsLessThan4KiB(t *testing.T) {
	b := Box{
		Duration: 1 * time.Hour,
		AEAD:     newAEAD(),
	}

	token, err := b.Seal(types.User{Email: "reallysuperduperlongemail@subdomain.example.test"})

	if err != nil {
		t.Fatal(err)
	}
	if len(token) > 4096 {
		t.Errorf("token must be less than 4 KiB: is %d bytes", len(token))
	}
}

func TestBox_Unseal(t *testing.T) {
	b := Box{AEAD: newAEAD()}
	e := "jane@example.test"
	pt, err := encodeToken(types.User{Email: e}, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, err := seal(b.AEAD, pt)
	if err != nil {
		t.Fatal(err)
	}

	u, err := b.Unseal(token)

	if err != nil {
		t.Fatal(err)
	}
	if u.Email != e {
		t.Errorf("expected email %q got %q", e, u.Email)
	}
}

func TestBox_Unseal_oldTokenExpires(t *testing.T) {
	b := Box{AEAD: newAEAD()}
	pt, err := encodeToken(types.User{}, -1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, err := seal(b.AEAD, pt)
	if err != nil {
		t.Fatal(err)
	}

	_, err = b.Unseal(token)

	if err != types.ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired got: %v", err)
	}
}
