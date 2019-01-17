package testutil

import (
	"net/http"
	"testing"
)

type ErrorLogin struct {
	*testing.T
}

func (l ErrorLogin) RequestCredentials(w http.ResponseWriter, r *http.Request) {
	l.Error("RequestCredentials should not be called")
}

type CounterLogin int

func (l *CounterLogin) RequestCredentials(w http.ResponseWriter, r *http.Request) {
	*l++
}
