package util

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
)

var RandomNonce = RandomNonceWithLength(32)

func RandomNonceWithLength(n int) func() (string, error) {
	return func() (s string, err error) {
		var b []byte
		b, err = ioutil.ReadAll(&io.LimitedReader{rand.Reader, int64((n*6 + 7) / 8)})
		s = base64.URLEncoding.EncodeToString(b)[:n]
		return
	}
}
