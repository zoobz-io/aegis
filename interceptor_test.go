//go:build testing

package aegis

import (
	"context"
	"errors"
	"testing"

	"github.com/zoobz-io/sctx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGuardRegistryRegisterAndGet(t *testing.T) {
	registry := NewGuardRegistry()

	if registry.Len() != 0 {
		t.Errorf("expected empty registry, got %d", registry.Len())
	}

	guard := &mockGuard{id: "test-guard"}
	registry.Register("/svc/Method", guard)

	got := registry.Get("/svc/Method")
	if got == nil {
		t.Fatal("expected guard for /svc/Method")
	}
	if got.ID() != "test-guard" {
		t.Errorf("expected guard ID 'test-guard', got %q", got.ID())
	}

	if registry.Len() != 1 {
		t.Errorf("expected 1 guard, got %d", registry.Len())
	}
}

func TestGuardRegistryUnguardedMethod(t *testing.T) {
	registry := NewGuardRegistry()

	got := registry.Get("/svc/UnguardedMethod")
	if got != nil {
		t.Error("expected nil for unguarded method")
	}
}

func TestUnaryGuardInterceptorUnguardedPassthrough(t *testing.T) {
	registry := NewGuardRegistry()
	interceptor := UnaryGuardInterceptor(registry, nil, "")

	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Unguarded"}
	resp, err := interceptor(context.Background(), nil, info, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
	if resp != "ok" {
		t.Errorf("expected 'ok', got %v", resp)
	}
}

func TestUnaryGuardInterceptorMissingToken(t *testing.T) {
	registry := NewGuardRegistry()
	registry.Register("/svc/Guarded", &mockGuard{id: "g1"})

	interceptor := UnaryGuardInterceptor(registry, nil, "")

	handler := func(ctx context.Context, req any) (any, error) {
		t.Error("handler should not be called")
		return nil, nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Guarded"}
	_, err := interceptor(context.Background(), nil, info, handler)
	if err == nil {
		t.Fatal("expected error for missing token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", st.Code())
	}
}

func TestUnaryGuardInterceptorValidationFailure(t *testing.T) {
	registry := NewGuardRegistry()
	registry.Register("/svc/Guarded", &mockGuard{
		id:          "g1",
		validateErr: errors.New("insufficient permissions"),
	})

	interceptor := UnaryGuardInterceptor(registry, nil, "")

	handler := func(ctx context.Context, req any) (any, error) {
		t.Error("handler should not be called")
		return nil, nil
	}

	// Add token to metadata
	md := metadata.Pairs(tokenMetadataKey, "fake-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Guarded"}
	_, err := interceptor(ctx, nil, info, handler)
	if err == nil {
		t.Fatal("expected error for validation failure")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestUnaryGuardInterceptorValidationSuccess(t *testing.T) {
	registry := NewGuardRegistry()
	registry.Register("/svc/Guarded", &mockGuard{id: "g1"})

	interceptor := UnaryGuardInterceptor(registry, nil, "")

	called := false
	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}

	md := metadata.Pairs(tokenMetadataKey, "valid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	info := &grpc.UnaryServerInfo{FullMethod: "/svc/Guarded"}
	resp, err := interceptor(ctx, nil, info, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
	if resp != "ok" {
		t.Errorf("expected 'ok', got %v", resp)
	}
}

func TestTokenFromMetadata(t *testing.T) {
	md := metadata.Pairs(tokenMetadataKey, "test-token-value")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	token, err := tokenFromMetadata(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(token) != "test-token-value" {
		t.Errorf("expected 'test-token-value', got %q", token)
	}
}

func TestTokenFromMetadataEmpty(t *testing.T) {
	ctx := context.Background()
	_, err := tokenFromMetadata(ctx)
	if err == nil {
		t.Fatal("expected error for missing metadata")
	}
}

// mockGuard implements sctx.Guard for testing.
type mockGuard struct {
	id          string
	validateErr error
}

func (g *mockGuard) ID() string                                               { return g.id }
func (g *mockGuard) Validate(_ context.Context, _ ...sctx.SignedToken) error   { return g.validateErr }
func (g *mockGuard) Permissions() []string                                     { return nil }
