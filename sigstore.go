// Package sigstore validates a sigstore bundle against the live (or
// cached) Sigstore TUF trust root via sigstore-go. Cross-ecosystem:
// handles any (digestAlg, digest) pair, so npm tarball (sha512) and
// GitHub artifact (sha256) attestations share the same path. PyPI,
// Maven, Cargo, and any other registry whose trusted-publishing flow
// emits a sigstore bundle work the same way.
//
// Stdlib + sigstore-go only — no project-specific deps, so it suits
// consumers that need bundle verification without baking sigstore-go
// into a larger surface.
//
// Consumers typically declare a one-method interface so verifiers
// (witness, SBOMit, plain in-toto) can swap. Verifier satisfies it
// structurally:
//
//	type ProvenanceVerifier interface {
//	    VerifyBundle(ctx context.Context, body []byte, alg string, digest []byte) error
//	}
package sigstore

import (
	"context"
	"encoding/json"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// Verifier wraps a Sigstore trust root. Construct via New.
type Verifier struct {
	root *root.TrustedRoot
}

// New binds the Verifier to a trust root. Fetch the root via
// sigstore-go's root.FetchTrustedRoot or FetchTrustedRootWithOptions
// (the latter supports a local cache directory).
func New(trustedRoot *root.TrustedRoot) *Verifier {
	return &Verifier{root: trustedRoot}
}

// VerifyBundle returns nil when the Fulcio cert chains to the trust
// root, the Rekor inclusion proof is valid, the DSSE signature
// matches the cert, and the in-toto subject digest matches
// (digestAlg, digest). digestAlg is "sha256" or "sha512".
func (v *Verifier) VerifyBundle(_ context.Context, bundleBody []byte, digestAlg string, digest []byte) error {
	if v.root == nil {
		return fmt.Errorf("sigstore: nil trust root")
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(bundleBody, &pb); err != nil {
		if err2 := json.Unmarshal(bundleBody, &pb); err2 != nil {
			return fmt.Errorf("parse sigstore bundle: %w", err)
		}
	}
	b, err := bundle.NewBundle(&pb)
	if err != nil {
		return fmt.Errorf("wrap sigstore bundle: %w", err)
	}
	sev, err := verify.NewVerifier(v.root,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("construct verifier: %w", err)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest(digestAlg, digest),
		verify.WithoutIdentitiesUnsafe(),
	)
	if _, err := sev.Verify(b, policy); err != nil {
		return fmt.Errorf("sigstore verify: %w", err)
	}
	return nil
}
