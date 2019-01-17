package testutil

import "testing"

func TestCounterLogin_RequestCredentials(t *testing.T) {
	var l CounterLogin

	l.RequestCredentials(nil, nil)
	if l != 1 {
		t.Errorf("counter should be 1, was %d", l)
	}
	l.RequestCredentials(nil, nil)
	if l != 2 {
		t.Errorf("counter should be 2, was %d", l)
	}
}
