package token

import (
	"crypto/cipher"
	"time"

	"go.jonnrb.io/webauth/types"
)

// Couples a duration and an AEAD cipher to create expiring, encrypted data that
// can be used as a token.
type Box struct {
	Duration time.Duration
	AEAD     cipher.AEAD
}

func (b *Box) Seal(u types.User) (token string, err error) {
	pt, err := encodeToken(u, b.Duration)
	if err != nil {
		return
	}
	token, err = seal(b.AEAD, pt)
	return
}

func (b *Box) Unseal(token string) (u types.User, err error) {
	pt, err := unseal(b.AEAD, token)
	if err != nil {
		return
	}
	u, err = decodeToken(pt)
	return
}
