//go:build testing

package aegis

import "context"

// WithTestSecurityContext injects a SecurityContext into the context for testing.
// This allows consumers to test gRPC server methods that depend on caller identity
// without standing up a real mTLS connection.
func WithTestSecurityContext(ctx context.Context, sc *SecurityContext) context.Context {
	return contextWithSecurityContext(ctx, sc)
}
