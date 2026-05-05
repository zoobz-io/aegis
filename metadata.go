package aegis

import (
	"context"

	"github.com/zoobz-io/sctx"
)

// Metadata carries the calling service's mesh-level identity.
// This is the M type parameter for sctx.Context[M] across all mesh services.
type Metadata struct {
	NodeID      string `json:"node_id"`
	ServiceName string `json:"service_name"`
}

// SecurityContext is the typed security context shared across all mesh services.
type SecurityContext = sctx.Context[Metadata]

// securityContextKey is the unexported key for storing SecurityContext in context.Context.
type securityContextKey struct{}

// SecurityContextFromContext extracts the SecurityContext from a context.
func SecurityContextFromContext(ctx context.Context) (*SecurityContext, bool) {
	sc, ok := ctx.Value(securityContextKey{}).(*SecurityContext)
	return sc, ok
}

// contextWithSecurityContext injects a SecurityContext into a context.
func contextWithSecurityContext(ctx context.Context, sc *SecurityContext) context.Context {
	return context.WithValue(ctx, securityContextKey{}, sc)
}
