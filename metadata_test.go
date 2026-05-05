package aegis

import (
	"context"
	"testing"
)

func TestMetadataFields(t *testing.T) {
	m := Metadata{NodeID: "node-1", ServiceName: "api"}
	if m.NodeID != "node-1" {
		t.Errorf("expected NodeID 'node-1', got %q", m.NodeID)
	}
	if m.ServiceName != "api" {
		t.Errorf("expected ServiceName 'api', got %q", m.ServiceName)
	}
}

func TestSecurityContextFromContextEmpty(t *testing.T) {
	ctx := context.Background()
	sc, ok := SecurityContextFromContext(ctx)
	if ok {
		t.Error("expected no security context in empty context")
	}
	if sc != nil {
		t.Error("expected nil security context")
	}
}

func TestSecurityContextRoundTrip(t *testing.T) {
	sc := &SecurityContext{
		Metadata: Metadata{NodeID: "node-1", ServiceName: "api"},
	}

	ctx := contextWithSecurityContext(context.Background(), sc)
	got, ok := SecurityContextFromContext(ctx)
	if !ok {
		t.Fatal("expected security context in context")
	}
	if got.Metadata.NodeID != "node-1" {
		t.Errorf("expected NodeID 'node-1', got %q", got.Metadata.NodeID)
	}
	if got.Metadata.ServiceName != "api" {
		t.Errorf("expected ServiceName 'api', got %q", got.Metadata.ServiceName)
	}
}
