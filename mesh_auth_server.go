package aegis

import (
	"context"
	"encoding/json"

	"github.com/zoobz-io/sctx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// meshAuthService implements the MeshAuthServer gRPC interface.
type meshAuthService struct {
	UnimplementedMeshAuthServer
	admin sctx.Admin[Metadata]
}

// NewMeshAuthService creates a new MeshAuth service backed by the given Admin.
func NewMeshAuthService(admin sctx.Admin[Metadata]) MeshAuthServer {
	return &meshAuthService{admin: admin}
}

// ExchangeToken verifies a signed assertion and returns a service token.
func (s *meshAuthService) ExchangeToken(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	caller, err := CallerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to extract caller identity: %v", err)
	}

	var assertion sctx.SignedAssertion
	if unmarshalErr := json.Unmarshal(req.Assertion, &assertion); unmarshalErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode assertion: %v", unmarshalErr)
	}

	token, err := s.admin.Generate(ctx, caller.Certificate, assertion)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "token exchange failed: %v", err)
	}

	fingerprint := sctx.GetFingerprint(caller.Certificate)
	sc, ok := s.admin.GetContext(ctx, fingerprint)
	if !ok {
		return nil, status.Errorf(codes.Internal, "context not found after generation")
	}

	return &TokenExchangeResponse{
		Token:     string(token),
		ExpiresAt: sc.ExpiresAt.Unix(),
	}, nil
}

// RevokeToken revokes a token by certificate fingerprint.
// Only self-revocation is permitted — the caller's certificate fingerprint
// must match the requested fingerprint.
func (s *meshAuthService) RevokeToken(ctx context.Context, req *RevokeTokenRequest) (*RevokeTokenResponse, error) {
	if req.Fingerprint == "" {
		return nil, status.Error(codes.InvalidArgument, "fingerprint is required")
	}

	caller, err := CallerFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "failed to extract caller identity: %v", err)
	}

	callerFingerprint := sctx.GetFingerprint(caller.Certificate)
	if req.Fingerprint != callerFingerprint {
		return nil, status.Error(codes.PermissionDenied, "can only revoke own token")
	}

	if err := s.admin.RevokeByFingerprint(ctx, req.Fingerprint); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke token: %v", err)
	}

	return &RevokeTokenResponse{}, nil
}

// MeshAuthRegistrar returns a ServiceRegistrar that registers the MeshAuth service.
func MeshAuthRegistrar(admin sctx.Admin[Metadata]) ServiceRegistrar {
	server := NewMeshAuthService(admin)
	return func(s *grpc.Server) {
		RegisterMeshAuthServer(s, server)
	}
}
