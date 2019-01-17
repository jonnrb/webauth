package token

import (
	"encoding/gob"
	"strings"
	"time"

	"go.jonnrb.io/webauth/types"
)

type token struct {
	Expires time.Time
	Email   string
}

func encodeToken(u types.User, duration time.Duration) (string, error) {
	t := token{
		Expires: time.Now().Add(duration),
		Email:   u.Email,
	}
	var b strings.Builder
	if err := gob.NewEncoder(&b).Encode(&t); err != nil {
		return "", err
	}
	return b.String(), nil
}

func decodeToken(s string) (u types.User, err error) {
	var t token
	err = gob.NewDecoder(strings.NewReader(s)).Decode(&t)
	if err != nil {
		return
	}
	if t.Expires.Before(time.Now()) {
		err = types.ErrTokenExpired
		return
	}
	u.Email = t.Email
	return
}
