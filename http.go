package oidcauth

import (
	"net/http"
	"strings"
)

// HTTPMiddleware is the middleware for HTTP handler.
type HTTPMiddleware func(http.Handler) http.Handler

// HTTPParams specifies the OIDC authentication settings for HTTP interceptor.
type HTTPParams struct {
	Params

	// HTTPHeaderName specifies the header name for retrieving the token.
	// Defaults to `Authorization`.
	HTTPHeaderName string

	// HTTPHeaderPrefix specifies the prefix for the header name.
	// Defaults to `Bearer`.
	HTTPHeaderValuePrefix string
}

func (p HTTPParams) defaults() HTTPParams {
	rv := p

	rv.Params = p.Params.defaults()
	if rv.HTTPHeaderName == "" {
		rv.HTTPHeaderName = "Authorization"
	}
	if rv.HTTPHeaderValuePrefix == "" {
		rv.HTTPHeaderValuePrefix = "Bearer"
	}

	return rv
}

// InterceptHTTP creates a HTTP middle for authenticating OIDC JWT token
// from the request.
func InterceptHTTP(params HTTPParams) HTTPMiddleware {
	params = params.defaults()

	loadTokenFromRequest := func(req *http.Request) string {
		v := strings.TrimSpace(req.Header.Get(params.HTTPHeaderName))
		if v == "" {
			return ""
		}

		v = strings.TrimPrefix(v, params.HTTPHeaderValuePrefix)
		v = strings.TrimSpace(v)

		return v
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := principalFromToken(
				r.Context(),
				params.Params,
				loadTokenFromRequest(r),
			)
			r = r.WithContext(ctxWithClaimsPrincipal(r.Context(), principal))
			h.ServeHTTP(w, r)
		})
	}
}

// PrincipalFromHTTPRequest retrieves the ClaimsPrincipal from the request.
// It returns unauthenticated principal if the request has not set.
func PrincipalFromHTTPRequest(req *http.Request) ClaimsPrincipal {
	return claimsPrincipalFromCtx(req.Context())
}
