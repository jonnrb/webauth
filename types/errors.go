package types

import (
	"net/http"

	"go.jonnrb.io/webauth/errors"
)

var ErrTokenExpired = errors.New(http.StatusUnauthorized, "token has expired", nil)
