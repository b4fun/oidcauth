package oidcauth

// Params specifies the OIDC authentication settings.
type Params struct {
	// IssuerURL specifies the issuer URL for discovering public signing keys.
	// Only URLs which use the `https://` scheme are accepted. Required.
	IssuerURL string

	// ClientID specifies the client ID for the OIDC client. Required.
	ClientID string

	// UserNameClaim specifies the JWT claim to use as the user name.
	// By default `sub`, which is expected to the be a unique identifier
	// of the end user. Optional.
	UserNameClaim string

	// RolesClaim specifies the JWT claim to use as the user roles.
	// If the clam is present it must be an array of strings.
	RolesClaim string

	// RequiredClaims specifies a group of required claims in the ID token.
	// Optional.
	RequiredClaims map[string]string

	// CAFile specifies the full path to the CA that singed the identity provider's
	// web certificate. Defaults to the host's root CAs.
	CAFile string
}

func (p Params) defaults() Params {
	rv := p

	if rv.UserNameClaim == "" {
		rv.UserNameClaim = "sub"
	}

	return rv
}
