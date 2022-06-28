package testoidcauth

import (
	"fmt"

	"github.com/b4fun/oidcauth"
)

// ClaimsPrincipal provides on-demand mock for oidcauth.ClaimsPrincipal type.
type ClaimsPrincipal struct {
	NameFunc            func() string
	HasRoleFunc         func(role string) bool
	ClaimsFunc          func() oidcauth.MapClaims
	BindClaimsFunc      func(v interface{}) error
	AuthenticateErrFunc func() error
}

var _ oidcauth.ClaimsPrincipal = (*ClaimsPrincipal)(nil)

func (cp *ClaimsPrincipal) Name() string {
	if cp.NameFunc != nil {
		return cp.NameFunc()
	}

	panic("not implemented")
}

func (cp *ClaimsPrincipal) HasRole(role string) bool {
	if cp.HasRoleFunc != nil {
		return cp.HasRoleFunc(role)
	}

	panic("not implemented")
}

func (cp *ClaimsPrincipal) Claims() oidcauth.MapClaims {
	if cp.ClaimsFunc != nil {
		return cp.ClaimsFunc()
	}

	panic("not implemented")
}

func (cp *ClaimsPrincipal) BindClaims(v interface{}) error {
	if cp.BindClaimsFunc != nil {
		return cp.BindClaimsFunc(v)
	}

	panic("not implemented")
}

func (cp *ClaimsPrincipal) AuthenticateErr() error {
	if cp.AuthenticateErrFunc != nil {
		return cp.AuthenticateErrFunc()
	}

	panic("not implemented")
}

// UnauthenticatedClaimsPrincipal creates an unauthenticated ClaimsPrincipal.
func UnauthenticatedClaimsPrincipal(err error) *ClaimsPrincipal {
	return &ClaimsPrincipal{
		NameFunc: func() string {
			return "unauthorized"
		},

		HasRoleFunc: func(role string) bool {
			return false
		},

		ClaimsFunc: func() oidcauth.MapClaims {
			return oidcauth.MapClaims{}
		},

		BindClaimsFunc: func(v interface{}) error {
			return fmt.Errorf("no claims")
		},

		AuthenticateErrFunc: func() error {
			if err != nil {
				return err
			}

			return oidcauth.ErrUnauthenticated
		},
	}
}
