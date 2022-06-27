package oidcauth

// MapClaims represents a set of claims in the token.
type MapClaims map[string]interface{}

// ClaimsPrincipal defines the principal object.
type ClaimsPrincipal interface {
	// Name returns the unique identity name of the principal.
	Name() string

	// HasRole checks if the principal has specified role.
	HasRole(role string) bool

	// Claims returns the claims from the token.
	Claims() MapClaims

	// BindClaims binds the token claims to given value receiver.
	BindClaims(v interface{}) error

	// AuthenticateErr returns error if the principal is unauthenticated.
	AuthenticateErr() error
}
