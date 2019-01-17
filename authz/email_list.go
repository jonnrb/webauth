package authz

import (
	"go.jonnrb.io/webauth/types"
)

type EmailList map[string]struct{}

func NewEmailList(emails []string) EmailList {
	m := make(EmailList)
	for _, e := range emails {
		m[e] = struct{}{}
	}
	return m
}

func (e EmailList) IsAuthorized(u types.User) bool {
	_, ok := e[u.Email]
	return ok
}
