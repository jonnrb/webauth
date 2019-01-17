package util

import "testing"

func assertLength(t *testing.T, s string, l int) {
	if len(s) != l {
		t.Errorf("expected %d byte nonce got %d bytes", l, len(s))
	}
}

func TestRandomNonce(t *testing.T) {
	n, err := RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	assertLength(t, n, 32)
}

func TestRandomNonceWithLength(t *testing.T) {
	n, err := RandomNonceWithLength(123)()
	if err != nil {
		t.Fatal(err)
	}
	assertLength(t, n, 123)

	n, err = RandomNonceWithLength(567)()
	if err != nil {
		t.Fatal(err)
	}
	assertLength(t, n, 567)

	n, err = RandomNonceWithLength(6)()
	if err != nil {
		t.Fatal(err)
	}
	assertLength(t, n, 6)
}
