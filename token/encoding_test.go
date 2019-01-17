package token

import (
	"testing"
	"time"

	"go.jonnrb.io/webauth/types"
)

func TestEncodeToken_numBytes(t *testing.T) {
	tok, err := encodeToken(types.User{Email: "jane@domain.test"}, 1*time.Hour)
	expectedSize := 99
	if err != nil {
		t.Error(err)
	} else if len(tok) != expectedSize {
		t.Errorf("expected %d bytes got %d bytes", expectedSize, len(tok))
	}
}
