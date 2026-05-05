package aegis

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/zoobz-io/sctx"
)

// NewAdmin creates an sctx.Admin[Metadata] from a private key and trusted CA pool.
func NewAdmin(privateKey crypto.PrivateKey, trustedCAs *x509.CertPool) (sctx.Admin[Metadata], error) {
	admin, err := sctx.NewAdminService[Metadata](privateKey, trustedCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin: %w", err)
	}

	if err := admin.SetPolicy(DefaultMeshPolicy()); err != nil {
		return nil, fmt.Errorf("failed to set policy: %w", err)
	}

	cache := sctx.NewBoundedMemoryCache[Metadata](sctx.CacheOptions{
		MaxSize:         1000,
		CleanupInterval: 5 * time.Minute,
	})
	if err := admin.SetCache(cache); err != nil {
		return nil, fmt.Errorf("failed to set cache: %w", err)
	}

	return admin, nil
}

// NewAdminFromKeychain creates an Admin by loading keys from a Keychain.
func NewAdminFromKeychain(ctx context.Context, keychain Keychain, id string) (sctx.Admin[Metadata], error) {
	key, err := keychain.LoadPrivateKey(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	fk, ok := keychain.(*FileKeychain)
	if !ok {
		return nil, fmt.Errorf("keychain does not support CA pool loading")
	}

	caPool, err := fk.LoadCAPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load CA pool: %w", err)
	}

	return NewAdmin(key, caPool)
}

// DefaultMeshPolicy returns a ContextPolicy that populates Metadata from certificate fields.
// CN → NodeID, O (first) → ServiceName.
func DefaultMeshPolicy() sctx.ContextPolicy[Metadata] {
	return func(cert *x509.Certificate) (*sctx.Context[Metadata], error) {
		base, err := sctx.DefaultContextPolicy[Metadata]()(cert)
		if err != nil {
			return nil, err
		}

		base.Metadata = Metadata{
			NodeID:      cert.Subject.CommonName,
			ServiceName: firstOrEmpty(cert.Subject.Organization),
		}

		return base, nil
	}
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
