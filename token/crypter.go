package token

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
)

func seal(aead cipher.AEAD, s string) (string, error) {
	r := io.LimitedReader{rand.Reader, int64(aead.NonceSize())}
	nonce, err := ioutil.ReadAll(&r)
	if err != nil {
		return "", err
	}

	pt := []byte(s)
	ct := append(nonce, aead.Seal(nil, nonce, pt, nil)...)
	return base64.URLEncoding.EncodeToString(ct), nil
}

func unseal(aead cipher.AEAD, s string) (string, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	nonce, ct := b[:aead.NonceSize()], b[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
