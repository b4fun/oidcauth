package oidcauth_test

import (
	"fmt"
	"net/http"

	"github.com/b4fun/oidcauth"
)

func ExampleHTTPParams() {
	params := oidcauth.HTTPParams{
		Params: oidcauth.Params{
			IssuerURL:     "https://accounts.google.com",
			ClientID:      "test-client",
			UserNameClaim: "sub",
			RolesClaim:    "roles",
		},
	}

	httpHandler := oidcauth.InterceptHTTP(params)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := oidcauth.PrincipalFromHTTPRequest(r)

			err := principal.AuthenticateErr()
			fmt.Printf("authenticate err: %s", err)
		}),
	)

	httpServer := &http.Server{
		Addr:    ":8080",
		Handler: httpHandler,
	}
	go func() {
		httpServer.ListenAndServe()
	}()

	req, err := http.NewRequest("GET", "http://localhost:8080", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3N1ZXIiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20ifQ.Rp01XsySaZ8PAnSxG6oGeVol_fBnnQBWfSEnM91tHfc")
	// uncomment to start the request
	// http.DefaultClient.Do(req)
}
