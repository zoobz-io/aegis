//go:build testing

package aegis

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zoobz-io/sctx"
)

func TestNewAdmin(t *testing.T) {
	sctx.ResetAdminForTesting()

	priv, caPool := generateTestAdminDeps(t)

	admin, err := NewAdmin(priv, caPool)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin == nil {
		t.Fatal("expected non-nil admin")
	}
}

func TestNewAdminFromKeychain(t *testing.T) {
	sctx.ResetAdminForTesting()

	dir := t.TempDir()
	writeTestKey(t, dir, "node-1")
	writeTestCACert(t, dir)

	kc := NewFileKeychain(dir)
	admin, err := NewAdminFromKeychain(context.Background(), kc, "node-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if admin == nil {
		t.Fatal("expected non-nil admin")
	}
}

func TestDefaultMeshPolicy(t *testing.T) {
	policy := DefaultMeshPolicy()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	_ = priv

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "node-1",
			Organization: []string{"api-service"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	sc, err := policy(cert)
	if err != nil {
		t.Fatalf("policy returned error: %v", err)
	}

	if sc.Metadata.NodeID != "node-1" {
		t.Errorf("expected NodeID 'node-1', got %q", sc.Metadata.NodeID)
	}
	if sc.Metadata.ServiceName != "api-service" {
		t.Errorf("expected ServiceName 'api-service', got %q", sc.Metadata.ServiceName)
	}
}

func generateTestAdminDeps(t *testing.T) (ed25519.PrivateKey, *x509.CertPool) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return priv, pool
}
