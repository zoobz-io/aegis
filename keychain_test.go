package aegis

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileKeychainLoadPrivateKey(t *testing.T) {
	dir := t.TempDir()
	writeTestKey(t, dir, "test")

	kc := NewFileKeychain(dir)
	key, err := kc.LoadPrivateKey(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestFileKeychainLoadCertificate(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "test")

	kc := NewFileKeychain(dir)
	cert, err := kc.LoadCertificate(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
	if cert.Subject.CommonName != "test" {
		t.Errorf("expected CN 'test', got %q", cert.Subject.CommonName)
	}
}

func TestFileKeychainLoadCAPool(t *testing.T) {
	dir := t.TempDir()
	writeTestCACert(t, dir)

	kc := NewFileKeychain(dir)
	pool, err := kc.LoadCAPool()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
}

func TestFileKeychainMissingFile(t *testing.T) {
	kc := NewFileKeychain(t.TempDir())
	_, err := kc.LoadPrivateKey(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFileKeychainMissingCert(t *testing.T) {
	kc := NewFileKeychain(t.TempDir())
	_, err := kc.LoadCertificate(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error for missing cert")
	}
}

// test helpers

func writeTestKey(t *testing.T, dir, id string) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(dir, id+"-key.pem")
	if err := os.WriteFile(path, pemBlock, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	return priv
}

func writeTestCert(t *testing.T, dir, id string) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   id,
			Organization: []string{"test-service"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	path := filepath.Join(dir, id+"-cert.pem")
	if err := os.WriteFile(path, pemBlock, 0644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	return cert, priv
}

func writeTestCACert(t *testing.T, dir string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	path := filepath.Join(dir, "ca-cert.pem")
	if err := os.WriteFile(path, pemBlock, 0644); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}
}
