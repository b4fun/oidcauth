package oidcauth

import "context"

type ctxKeyClaimsPrincipalT int

var ctxKeyClaimsPrincipal ctxKeyClaimsPrincipalT

func ctxWithClaimsPrincipal(
	ctx context.Context,
	v ClaimsPrincipal,
) context.Context {
	return context.WithValue(ctx, ctxKeyClaimsPrincipal, v)
}

func claimsPrincipalFromCtx(ctx context.Context) ClaimsPrincipal {
	v, ok := ctx.Value(ctxKeyClaimsPrincipal).(ClaimsPrincipal)
	if ok {
		return v
	}

	return unauthenticatedClaimsPrincipal()
}
