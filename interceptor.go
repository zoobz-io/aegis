package aegis

import (
	"context"
	"sync"

	"github.com/zoobz-io/sctx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const tokenMetadataKey = "x-aegis-token"

// GuardRegistry maps gRPC method names to guards.
type GuardRegistry struct {
	mu     sync.RWMutex
	guards map[string]sctx.Guard
}

// NewGuardRegistry creates an empty guard registry.
func NewGuardRegistry() *GuardRegistry {
	return &GuardRegistry{
		guards: make(map[string]sctx.Guard),
	}
}

// Register maps a gRPC method to a guard.
func (gr *GuardRegistry) Register(method string, guard sctx.Guard) {
	gr.mu.Lock()
	defer gr.mu.Unlock()
	gr.guards[method] = guard
}

// Get returns the guard for a method, or nil if unguarded.
func (gr *GuardRegistry) Get(method string) sctx.Guard {
	gr.mu.RLock()
	defer gr.mu.RUnlock()
	return gr.guards[method]
}

// Len returns the number of registered guards.
func (gr *GuardRegistry) Len() int {
	gr.mu.RLock()
	defer gr.mu.RUnlock()
	return len(gr.guards)
}

// guardInterceptorState holds shared state for interceptors.
type guardInterceptorState struct {
	registry  *GuardRegistry
	admin     sctx.Admin[Metadata]
	nodeToken sctx.SignedToken
}

// UnaryGuardInterceptor returns a gRPC unary interceptor that validates tokens against guards.
// Unguarded methods (no guard registered) pass through — protected by mTLS alone.
func UnaryGuardInterceptor(registry *GuardRegistry, admin sctx.Admin[Metadata], nodeToken sctx.SignedToken) grpc.UnaryServerInterceptor {
	state := &guardInterceptorState{registry: registry, admin: admin, nodeToken: nodeToken}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := state.validateRequest(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamGuardInterceptor returns a gRPC stream interceptor that validates tokens against guards.
func StreamGuardInterceptor(registry *GuardRegistry, admin sctx.Admin[Metadata], nodeToken sctx.SignedToken) grpc.StreamServerInterceptor {
	state := &guardInterceptorState{registry: registry, admin: admin, nodeToken: nodeToken}
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := state.validateRequest(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

// validateRequest performs guard validation and returns an enriched context.
func (s *guardInterceptorState) validateRequest(ctx context.Context, method string) (context.Context, error) {
	guard := s.registry.Get(method)
	if guard == nil {
		return ctx, nil
	}

	callerToken, err := tokenFromMetadata(ctx)
	if err != nil {
		return ctx, status.Errorf(codes.Unauthenticated, "missing or invalid token: %v", err)
	}

	if err := guard.Validate(ctx, s.nodeToken, callerToken); err != nil {
		return ctx, status.Errorf(codes.PermissionDenied, "guard validation failed: %v", err)
	}

	// Extract caller's fingerprint from the mTLS context to look up security context
	caller, err := CallerFromContext(ctx)
	if err == nil {
		fingerprint := sctx.GetFingerprint(caller.Certificate)
		if sc, ok := s.admin.GetContext(ctx, fingerprint); ok {
			ctx = contextWithSecurityContext(ctx, sc)
		}
	}

	return ctx, nil
}

// tokenFromMetadata extracts the aegis token from gRPC metadata.
func tokenFromMetadata(ctx context.Context) (sctx.SignedToken, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no metadata in request")
	}

	values := md.Get(tokenMetadataKey)
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "no token in metadata")
	}

	return sctx.SignedToken(values[0]), nil
}

// wrappedStream wraps a grpc.ServerStream with a modified context.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (ws *wrappedStream) Context() context.Context {
	return ws.ctx
}
