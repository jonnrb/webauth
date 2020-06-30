package errors

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

type HTTPError struct {
	Status             int
	PresentableMessage string
	Inner              error
}

func New(status int, msg string, cause error) HTTPError {
	return HTTPError{
		Status:             status,
		PresentableMessage: msg,
		Inner:              cause,
	}
}

func WithCause(reason string, cause error) (err HTTPError) {
	if httpErr, ok := cause.(HTTPError); ok {
		err = httpErr
	} else {
		err.Inner = cause
	}
	if err.Inner != nil {
		err.Inner = fmt.Errorf("%s: %v", reason, err.Inner)
	} else {
		err.Inner = fmt.Errorf(reason)
	}
	return
}

func (e HTTPError) Unwrap() error {
	return e.Inner
}

func (e HTTPError) Error() string {
	var b strings.Builder
	if e.Status != 0 {
		b.WriteString(fmt.Sprintf("HTTP %d", e.Status))
	} else {
		b.WriteString("HTTP error")
	}
	if e.PresentableMessage != "" {
		b.WriteString(fmt.Sprintf(" %q", e.PresentableMessage))
	}
	if e.Inner != nil {
		b.WriteString(fmt.Sprintf(": %v", e.Inner))
	}
	return b.String()
}

func (e HTTPError) msgOrDefault() string {
	if e.PresentableMessage != "" {
		return e.PresentableMessage
	} else {
		return "internal error"
	}
}

func (e HTTPError) statusOrDefault() int {
	if e.Status != 0 {
		return e.Status
	} else {
		return http.StatusInternalServerError
	}
}

func (e HTTPError) WriteHTTP(w http.ResponseWriter) {
	http.Error(w, e.msgOrDefault(), e.statusOrDefault())
}

func WriteError(w http.ResponseWriter, err error) {
	httpErr, ok := err.(HTTPError)
	if !ok {
		httpErr.Inner = err
	}
	httpErr.WriteHTTP(w)
	log.Println(httpErr)
}
