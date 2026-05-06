package aegis

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Keychain loads cryptographic keys and certificates from infrastructure.
type Keychain interface {
	LoadPrivateKey(ctx context.Context, id string) (crypto.PrivateKey, error)
	LoadCertificate(ctx context.Context, id string) (*x509.Certificate, error)
	LoadTrustedCAs(ctx context.Context) (*x509.CertPool, error)
}

// FileKeychain loads keys and certificates from PEM files on disk.
type FileKeychain struct {
	dir string
}

// NewFileKeychain creates a Keychain that loads from the given directory.
// Keys are expected at {dir}/{id}-key.pem, certificates at {dir}/{id}-cert.pem.
func NewFileKeychain(dir string) *FileKeychain {
	return &FileKeychain{dir: dir}
}

// LoadPrivateKey loads a PEM-encoded private key from {dir}/{id}-key.pem.
func (fk *FileKeychain) LoadPrivateKey(_ context.Context, id string) (crypto.PrivateKey, error) {
	path := filepath.Join(fk.dir, fmt.Sprintf("%s-key.pem", filepath.Base(id)))
	data, err := os.ReadFile(path) //nolint:gosec // path is sanitized via filepath.Base
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	// Try PKCS8 first (works for Ed25519, ECDSA, RSA)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	// Fall back to EC key
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return ecKey, nil
	}

	// Fall back to PKCS1 RSA
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return rsaKey, nil
	}

	return nil, fmt.Errorf("failed to parse private key from %s: unsupported format", path)
}

// LoadCertificate loads a PEM-encoded certificate from {dir}/{id}-cert.pem.
func (fk *FileKeychain) LoadCertificate(_ context.Context, id string) (*x509.Certificate, error) {
	path := filepath.Join(fk.dir, fmt.Sprintf("%s-cert.pem", filepath.Base(id)))
	data, err := os.ReadFile(path) //nolint:gosec // path is sanitized via filepath.Base
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from %s: %w", path, err)
	}

	return cert, nil
}

// LoadTrustedCAs loads a PEM-encoded CA certificate pool from {dir}/ca-cert.pem.
func (fk *FileKeychain) LoadTrustedCAs(_ context.Context) (*x509.CertPool, error) {
	path := filepath.Join(fk.dir, "ca-cert.pem")
	data, err := os.ReadFile(path) //nolint:gosec // fixed path, no user input
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file %s: %w", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", path)
	}

	return pool, nil
}
