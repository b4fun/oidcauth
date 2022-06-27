package oidcauth_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/b4fun/oidcauth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

// keyIDFromPublicKey derives a key ID non-reversibly from a public key.
//
// The Key ID is field on a given on JWTs and JWKs that help relying parties
// pick the correct key for verification when the identity party advertises
// multiple keys.
//
// Making the derivation non-reversible makes it impossible for someone to
// accidentally obtain the real key from the key ID and use it for token
// validation.
func keyIDFromPublicKey(publicKey *rsa.PublicKey) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %w", err)
	}

	hasher := crypto.SHA256.New()
	_, _ = hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

func jwksFromPrivateKey(t *testing.T, privateKey *rsa.PrivateKey) string {
	publicKey := &privateKey.PublicKey
	keyID, err := keyIDFromPublicKey(publicKey)
	require.NoError(t, err)

	jwks := new(jose.JSONWebKeySet)
	jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       publicKey,
		KeyID:     keyID,
		Use:       "sig",
	})

	b, err := json.MarshalIndent(jwks, "", "  ")
	require.NoError(t, err)

	return string(b)
}

type idProviderT struct {
	JWKS                   string
	OpenIDMetadataTemplate string

	privateKey *rsa.PrivateKey
	*httptest.Server
}

func newIDProvider(t *testing.T) *idProviderT {
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	require.NoError(t, err)

	rv := &idProviderT{
		privateKey: privateKey,
		JWKS:       jwksFromPrivateKey(t, privateKey),
		OpenIDMetadataTemplate: `
{
	"issuer": "ISSUER_URL",
	"jwks_uri": "ISSUER_URLopenid/v1/jwks",
	"response_types_supported": ["id_token"],
	"subject_types_supported": ["public"],
	"id_token_signing_alg_values_supported": ["RS256"]
}
	`,
	}

	rv.Server = httptest.NewUnstartedServer(rv.mux(t))

	return rv
}

func (idp *idProviderT) mux(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(
		"/openid/v1/jwks",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log("requesting /openid/v1/jwks")

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(idp.JWKS))
		}),
	)
	mux.Handle(
		"/.well-known/openid-configuration",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Log("requesting /.well-known/openid-configuration")

			w.Header().Set("Content-Type", "application/json")
			b := strings.ReplaceAll(
				idp.OpenIDMetadataTemplate,
				"ISSUER_URL", idp.IssuerURL(),
			)
			w.Write([]byte(b))
		}),
	)

	return mux
}

func (idp *idProviderT) IssuerURL() string {
	return idp.URL + "/"
}

func (idp *idProviderT) CAFile(t *testing.T) string {
	cert := idp.Certificate()
	require.NotNil(t, cert)

	path := filepath.Join(t.TempDir(), "ca.pem")
	b := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	err := os.WriteFile(path, pem.EncodeToMemory(b), 0644)
	require.NoError(t, err)

	return path
}

func (idp *idProviderT) JWT(t *testing.T, claims jwt.Claims) string {
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		claims,
	)
	tokenSigned, err := token.SignedString(idp.privateKey)
	require.NoError(t, err)

	return tokenSigned
}

func convertWithDefault[T any, U any](
	computeDefaultValue func() T,
	convert func(T) U,
) func(...func(*T)) U {
	return func(mutateFuncs ...func(*T)) U {
		v := computeDefaultValue()

		for _, m := range mutateFuncs {
			m(&v)
		}

		return convert(v)
	}
}

func withDefault[T any](computeDefaultValue func() T) func(...func(*T)) T {
	return convertWithDefault(computeDefaultValue, func(t T) T { return t })
}

type claimsT struct {
	jwt.RegisteredClaims

	Roles    jwt.ClaimStrings `json:"roles,omitempty"`
	UID      string           `json:"uid,omitempty"`
	ClaimFoo string           `json:"foo,omitempty"`
}

func TestInterceptHTTP(t *testing.T) {
	idP := newIDProvider(t)
	idP.StartTLS()
	defer idP.Close()

	const (
		defaultClientID = "test-client-id"
		defaultSubject  = "test-subject"
		defaultRole     = "test-role"
		defaultUID      = "test-uid"
	)

	defaultParams := withDefault(func() oidcauth.HTTPParams {
		return oidcauth.HTTPParams{
			Params: oidcauth.Params{
				IssuerURL: idP.IssuerURL(),
				ClientID:  defaultClientID,
				CAFile:    idP.CAFile(t),
			},
			HTTPHeaderName:        "Authorization",
			HTTPHeaderValuePrefix: "Bearer",
		}
	})

	jwtWithClaimsT := convertWithDefault(
		func() claimsT {
			return claimsT{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    idP.IssuerURL(),
					Audience:  jwt.ClaimStrings{defaultClientID},
					Subject:   defaultSubject,
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}
		},
		func(claims claimsT) string {
			return idP.JWT(t, claims)
		},
	)

	testCases := []struct {
		params         oidcauth.HTTPParams
		jwt            string
		checkPrincipal func(t *testing.T, principal oidcauth.ClaimsPrincipal)
	}{
		// empty token
		{
			params: defaultParams(),
			jwt:    "",
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.Error(t, err)
			},
		},
		// invalid token
		{
			params: defaultParams(),
			jwt:    "foobar",
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.Error(t, err)
			},
		},
		// invalid client id
		{
			params: defaultParams(),
			jwt: jwtWithClaimsT(func(claims *claimsT) {
				claims.Audience = jwt.ClaimStrings{"invalid-client-id"}
			}),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.Error(t, err)
				// oidc: expected audience ...
				assert.Contains(t, err.Error(), "expected audience")
			},
		},
		// issuer mismatch
		{
			params: defaultParams(),
			jwt: jwtWithClaimsT(func(claims *claimsT) {
				claims.Issuer = "foobar"
			}),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.Error(t, err)
				// oidc: id token issued by a different provider ...
				assert.Contains(t, err.Error(), "oidc: id token issued by a different provider")
			},
		},
		// expired
		{
			params: defaultParams(),
			jwt: jwtWithClaimsT(func(claims *claimsT) {
				claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
			}),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.Error(t, err)
				// oidc: token is expired ...
				assert.Contains(t, err.Error(), "oidc: token is expired")
			},
		},
		// missing user name claims
		{
			params: defaultParams(),
			jwt: jwtWithClaimsT(func(claims *claimsT) {
				claims.Subject = ""
			}),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.Error(t, err)
				// missing claim: sub...
				assert.Contains(t, err.Error(), "missing claim: sub")
			},
		},
		// missing required claims
		{
			params: defaultParams(func(params *oidcauth.HTTPParams) {
				params.Params.RequiredClaims = map[string]string{
					"xxx": "yyy",
				}
			}),
			jwt: jwtWithClaimsT(),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.Error(t, err)
				// missing claim: xxx=yyy ...
				assert.Contains(t, err.Error(), "missing claim: xxx=yyy")
			},
		},

		// basic case
		{
			params: defaultParams(),
			jwt:    jwtWithClaimsT(),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.NoError(t, err)
				assert.Equal(t, defaultSubject, principal.Name())
			},
		},
		// JWT with roles
		{
			params: defaultParams(func(params *oidcauth.HTTPParams) {
				params.RolesClaim = "roles"
			}),
			jwt: jwtWithClaimsT(func(claims *claimsT) {
				claims.Roles = jwt.ClaimStrings{defaultRole}
			}),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.NoError(t, err)
				assert.Equal(t, defaultSubject, principal.Name())
				assert.True(t, principal.HasRole(defaultRole))
				assert.False(t, principal.HasRole("foobar"))
			},
		},
		// JWT with different user name claims
		{
			params: defaultParams(func(params *oidcauth.HTTPParams) {
				params.UserNameClaim = "uid"
				params.RolesClaim = "roles"
			}),
			jwt: jwtWithClaimsT(func(claims *claimsT) {
				claims.Roles = jwt.ClaimStrings{defaultRole}
				claims.UID = defaultUID
			}),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.NoError(t, err)
				assert.Equal(t, defaultUID, principal.Name())
				assert.True(t, principal.HasRole(defaultRole))
			},
		},
		// JWT with required claims
		{
			params: defaultParams(func(params *oidcauth.HTTPParams) {
				params.RequiredClaims = map[string]string{"foo": "bar"}
			}),
			jwt: jwtWithClaimsT(func(claims *claimsT) {
				claims.ClaimFoo = "bar"
			}),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.NoError(t, err)
				assert.Equal(t, defaultSubject, principal.Name())

				var c claimsT
				err = principal.BindClaims(&c)
				assert.NoError(t, err)
				assert.Equal(t, defaultClientID, c.Audience[0])
				assert.Equal(t, defaultSubject, c.Subject)
			},
		},
		// load claims
		{
			params: defaultParams(func(params *oidcauth.HTTPParams) {
				params.RequiredClaims = map[string]string{"foo": "bar"}
			}),
			jwt: jwtWithClaimsT(func(claims *claimsT) {
				claims.ClaimFoo = "bar"
			}),
			checkPrincipal: func(t *testing.T, principal oidcauth.ClaimsPrincipal) {
				err := principal.AuthenticateErr()
				assert.NoError(t, err)

				var c claimsT
				err = principal.BindClaims(&c)
				assert.NoError(t, err)
				assert.Equal(t, defaultClientID, c.Audience[0])
				assert.Equal(t, defaultSubject, c.Subject)
				assert.Equal(t, "bar", c.ClaimFoo)

				mapClaims := principal.Claims()
				assert.Equal(t, defaultSubject, mapClaims["sub"])
				assert.Equal(t, "bar", mapClaims["foo"])
			},
		},
	}

	for idx := range testCases {
		c := testCases[idx]
		t.Run(fmt.Sprintf("test #%d", idx), func(t *testing.T) {
			md := oidcauth.InterceptHTTP(c.params)

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				principal := oidcauth.PrincipalFromHTTPRequest(r)
				assert.NotNil(t, principal)
				c.checkPrincipal(t, principal)
			})

			server := md(handler)

			req, err := http.NewRequest("GET", "http://example.com", nil)
			t.Logf("jwt is: %q", c.jwt)
			assert.NoError(t, err)
			req.Header.Set(
				c.params.HTTPHeaderName,
				c.params.HTTPHeaderValuePrefix+" "+c.jwt,
			)
			w := httptest.NewRecorder()

			server.ServeHTTP(w, req)
		})
	}
}
