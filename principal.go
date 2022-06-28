package oidcauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	ErrUnauthenticated = fmt.Errorf("unauthenticated")
	ErrMissingClaim    = fmt.Errorf("missing claim")
)

type unauthenticatedClaimsPrincipalT struct {
	err error
}

var _ ClaimsPrincipal = (*unauthenticatedClaimsPrincipalT)(nil)

func (cp *unauthenticatedClaimsPrincipalT) Name() string {
	return "unauthenticated"
}

func (cp *unauthenticatedClaimsPrincipalT) HasRole(role string) bool {
	return false
}

func (cp *unauthenticatedClaimsPrincipalT) Claims() MapClaims {
	return MapClaims{}
}

func (cp *unauthenticatedClaimsPrincipalT) BindClaims(v interface{}) error {
	return fmt.Errorf("no claims")
}

func (cp *unauthenticatedClaimsPrincipalT) AuthenticateErr() error {
	if cp.err != nil {
		return cp.err
	}
	return ErrUnauthenticated
}

func unauthenticatedClaimsPrincipalWithErr(err error) ClaimsPrincipal {
	return &unauthenticatedClaimsPrincipalT{
		err: err,
	}
}

func unauthenticatedClaimsPrincipal() ClaimsPrincipal {
	return unauthenticatedClaimsPrincipalWithErr(ErrUnauthenticated)
}

// PrincipalLoaderFunc loads a ClaimsPrincipal from given context and token.
type PrincipalLoaderFunc func(ctx context.Context, token string) ClaimsPrincipal

// CreatePrincipalLoader creates the PrincipalLoaderFunc from the given Params.
func CreatePrincipalLoader(params Params) (PrincipalLoaderFunc, error) {
	params = params.defaults()

	var httpClient *http.Client
	if params.CAFile != "" {
		var err error
		httpClient, err = httpClientWithCA(params.CAFile)
		if err != nil {
			err = fmt.Errorf("create http client from CA %s: %w", params.CAFile, err)
			return nil, err
		}
	}

	loader := func(ctx context.Context, token string) ClaimsPrincipal {
		if httpClient != nil {
			ctx = oidc.ClientContext(ctx, httpClient)
		}

		provider, err := oidc.NewProvider(ctx, params.IssuerURL)
		if err != nil {
			return unauthenticatedClaimsPrincipalWithErr(err)
		}

		verifier := provider.Verifier(&oidc.Config{
			ClientID: params.ClientID,
		})

		verifiedToken, err := verifier.Verify(ctx, token)
		if err != nil {
			return unauthenticatedClaimsPrincipalWithErr(err)
		}

		return newClaimsPrincipalFromToken(params, verifiedToken)
	}

	return loader, nil
}

func httpClientWithCA(caPath string) (*http.Client, error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	return client, nil
}

type claimsPrincipal struct {
	name            string
	roles           map[string]struct{}
	claims          []byte
	authenticateErr error
}

var _ ClaimsPrincipal = (*claimsPrincipal)(nil)

func (cp *claimsPrincipal) Name() string {
	return cp.name
}

func (cp *claimsPrincipal) HasRole(role string) bool {
	_, exists := cp.roles[role]
	return exists
}

func (cp *claimsPrincipal) Claims() MapClaims {
	rv := make(MapClaims)
	_ = cp.BindClaims(&rv)
	return rv
}

func (cp *claimsPrincipal) BindClaims(v interface{}) error {
	return json.Unmarshal(cp.claims, v)
}

func (cp *claimsPrincipal) AuthenticateErr() error {
	return cp.authenticateErr
}

func getFromMapClaims[T any](mc MapClaims, name string) T {
	v, exists := mc[name]
	if !exists {
		var empty T
		return empty
	}
	vv, ok := v.(T)
	if !ok {
		var empty T
		return empty
	}
	return vv
}

func newClaimsPrincipalFromToken(
	params Params,
	token *oidc.IDToken,
) ClaimsPrincipal {
	var claims MapClaims

	if err := token.Claims(&claims); err != nil {
		// failed to decode claims
		return unauthenticatedClaimsPrincipalWithErr(err)
	}

	claimsEncoded, err := json.Marshal(claims)
	if err != nil {
		// failed to encode back
		return unauthenticatedClaimsPrincipalWithErr(err)
	}

	name := getFromMapClaims[string](claims, params.UserNameClaim)
	if name == "" {
		return unauthenticatedClaimsPrincipalWithErr(
			fmt.Errorf("%w: %s", ErrMissingClaim, params.UserNameClaim),
		)
	}

	rv := &claimsPrincipal{
		name:   name,
		claims: claimsEncoded,
		roles:  map[string]struct{}{},
	}

	var roles []interface{}
	if params.RolesClaim != "" {
		roles = getFromMapClaims[[]interface{}](claims, params.RolesClaim)
	}

	for _, r := range roles {
		rv.roles[fmt.Sprint(r)] = struct{}{}
	}

	if params.RequiredClaims != nil {
		for requiredKey, requiredValue := range params.RequiredClaims {
			v, exists := claims[requiredKey]
			if !exists || v != requiredValue {
				return unauthenticatedClaimsPrincipalWithErr(
					fmt.Errorf("%w: %s=%s", ErrMissingClaim, requiredKey, requiredValue),
				)
			}
		}
	}

	return rv
}
