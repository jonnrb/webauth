package main

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"go.jonnrb.io/webauth/authn"
	"go.jonnrb.io/webauth/authn/google"
	"go.jonnrb.io/webauth/authn/util"
	"go.jonnrb.io/webauth/authz"
	"go.jonnrb.io/webauth/cookie"
	"go.jonnrb.io/webauth/token"
)

var (
	host         = flag.String("host", "", "hostname of the auth server")
	whitelist    = flag.String("whitelist", "", "emails to allow")
	cookieName   = flag.String("cookie_name", "_webauth", "name of the cookie to use")
	cookieDomain = flag.String("cookie_domain", "", "domain to assign the cookie to")
	cookieExpiry = flag.Duration("cookie_expiry", 24*time.Hour, "how long an authentication cookie is valid")
	csrfExpiry   = flag.Duration("csrf_expiry", 15*time.Minute, "how long an oauth roundtrip can last")
)

func newOauthConfig() authn.OauthConfig {
	clientID, clientSecret := os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "env vars CLIENT_ID and CLIENT_SECRET should be set")
		os.Exit(1)
	}
	return google.New(clientID, clientSecret, "https://"+*host)
}

func newAEAD() cipher.AEAD {
	secret := os.Getenv("COOKIE_SECRET")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "env var COOKIE_SECRET should be set")
		os.Exit(1)
	}
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating AEAD: %v", err)
		os.Exit(1)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating AEAD: %v", err)
		os.Exit(1)
	}
	return aead
}

func newHandler() *Handler {
	cookieAuthn := &authn.CookieAuthenticator{
		AuthCookieRecipe: &cookie.EphemeralRecipe{
			Name:     *cookieName,
			Domain:   *cookieDomain,
			Duration: *cookieExpiry,
		},
		TokenBox: &token.Box{
			Duration: *cookieExpiry,
			AEAD:     newAEAD(),
		},
	}
	oauthAuthn := &authn.OauthAuthenticator{
		Backend: newOauthConfig(),
		CSRFCookieRecipe: &cookie.EphemeralRecipe{
			Name:     *cookieName + "_csrf",
			Domain:   *cookieDomain,
			Duration: *csrfExpiry,
		},
		Nonce: util.RandomNonce,
	}
	return &Handler{
		EUCBox:        cookieAuthn,
		Authenticator: oauthAuthn,
		Login:         oauthAuthn,
		Authorizer:    authz.NewEmailList(strings.Split(*whitelist, ",")),
	}
}

func main() {
	flag.Parse()
	if *host == "" || *cookieDomain == "" || *whitelist == "" {
		flag.Usage()
		os.Exit(1)
	}

	(&http.Server{
		Addr:         ":8080",
		Handler:      newHandler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  5 * time.Second,
	}).ListenAndServe()
}
