// Package sigstoreverifier validates a sigstore bundle against the
// live (or cached) Sigstore TUF trust root via sigstore-go. Cross-
// ecosystem by design: handles any (digestAlg, digest) pair, so npm
// tarball (sha512) and GitHub artifact (sha256) attestations use the
// same code path. PyPI, Maven, Cargo, and any other registry whose
// trusted-publishing flow emits a sigstore bundle work the same way.
//
// The package has no project-specific dependencies — only sigstore-go
// — so it suits any consumer that needs to verify an attestation
// without baking sigstore-go into a larger surface.
//
// Consumers typically declare their own one-method interface to swap
// verifiers (witness, SBOMit, plain in-toto). Verifier satisfies
// such an interface structurally:
//
//	type ProvenanceVerifier interface {
//	    VerifyBundle(ctx context.Context, body []byte, alg string, digest []byte) error
//	}
package sigstoreverifier

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

// Verifier wraps a Sigstore trust root. Construct via New; pass into
// any code path that expects a "verify this bundle against an
// artifact" affordance.
type Verifier struct {
	root *root.TrustedRoot
}

// New returns a Verifier bound to the supplied trust root. Callers
// fetch the root via sigstore-go's root.FetchTrustedRoot or
// root.FetchTrustedRootWithOptions (the latter supports a local
// cache directory).
func New(trustedRoot *root.TrustedRoot) *Verifier {
	return &Verifier{root: trustedRoot}
}

// VerifyBundle returns nil when bundleBody is a sigstore bundle
// whose Fulcio cert chains to the supplied trust root, whose Rekor
// inclusion proof is valid, whose DSSE envelope signature matches,
// and whose in-toto subject digest matches the supplied
// (digestAlg, digest) pair. digestAlg is "sha256" or "sha512";
// digest is the raw bytes of that hash over the artifact.
func (v *Verifier) VerifyBundle(_ context.Context, bundleBody []byte, digestAlg string, digest []byte) error {
	if v.root == nil {
		return fmt.Errorf("sigstoreverifier: nil trust root")
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
