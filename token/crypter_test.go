package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func stubRandReader() func() {
	realRandReader := rand.Reader
	rand.Reader = zeroReader{}
	return func() {
		rand.Reader = realRandReader
	}
}

func newAEAD() cipher.AEAD {
	block, err := aes.NewCipher([]byte("qwertyqwertyqwertyqwertyqwertyzz"))
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func ExampleSeal() {
	defer stubRandReader()()

	ct, err := seal(newAEAD(), "foobar")
	if err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println(ct)
	}
	// Output:
	// AAAAAAAAAAAAAAAA7ukz6iCWDBnOktYjv7C9dU3bxUBNxg==
}

func ExampleUnseal() {
	defer stubRandReader()()

	ct, err := unseal(newAEAD(), "AAAAAAAAAAAAAAAA7ukz6iCWDBnOktYjv7C9dU3bxUBNxg==")
	if err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println(ct)
	}
	// Output:
	// foobar
}
