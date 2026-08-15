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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

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

// VerificationResult contains metadata whose integrity was established by
// bundle verification. CertificateIdentity and CertificateIssuer describe
// the signer but do not authorize it.
type VerificationResult struct {
	CertificateIdentity string
	CertificateIssuer   string
	TransparencyLogs    []TransparencyLog
	Subjects            []Subject
	PredicateType       string
	Statement           json.RawMessage
	Predicate           json.RawMessage
}

// TransparencyLog identifies a log and the verified time at which it
// integrated the bundle entry. ID is the log's hex-encoded key ID.
type TransparencyLog struct {
	ID             string
	URI            string
	IntegratedTime time.Time
}

// Subject is an in-toto subject from the verified statement.
type Subject struct {
	Name   string
	URI    string
	Digest map[string]string
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
func (v *Verifier) VerifyBundle(ctx context.Context, bundleBody []byte, digestAlg string, digest []byte) error {
	_, err := v.VerifyBundleDetailed(ctx, bundleBody, digestAlg, digest)
	return err
}

// VerifyBundleDetailed verifies a bundle like VerifyBundle and returns
// metadata covered by that verification. The result describes the signer and
// signed statement. Deciding whether the signer is authorized remains the
// caller's responsibility.
func (v *Verifier) VerifyBundleDetailed(_ context.Context, bundleBody []byte, digestAlg string, digest []byte) (*VerificationResult, error) {
	if v.root == nil {
		return nil, fmt.Errorf("sigstore: nil trust root")
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(bundleBody, &pb); err != nil {
		if err2 := json.Unmarshal(bundleBody, &pb); err2 != nil {
			return nil, fmt.Errorf("parse sigstore bundle: %w", err)
		}
	}
	b, err := bundle.NewBundle(&pb)
	if err != nil {
		return nil, fmt.Errorf("wrap sigstore bundle: %w", err)
	}
	sev, err := verify.NewVerifier(v.root,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("construct verifier: %w", err)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest(digestAlg, digest),
		verify.WithoutIdentitiesUnsafe(),
	)
	verified, err := sev.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("sigstore verify: %w", err)
	}
	result, err := verificationResult(b, verified, v.root.RekorLogs())
	if err != nil {
		return nil, fmt.Errorf("build verification result: %w", err)
	}
	return result, nil
}

func verificationResult(b *bundle.Bundle, verified *verify.VerificationResult, rekorLogs map[string]*root.TransparencyLog) (*VerificationResult, error) {
	result := &VerificationResult{}
	if verified.Signature != nil && verified.Signature.Certificate != nil {
		result.CertificateIdentity = verified.Signature.Certificate.SubjectAlternativeName
		result.CertificateIssuer = verified.Signature.Certificate.Issuer
	}
	for _, timestamp := range verified.VerifiedTimestamps {
		if timestamp.Type != "Tlog" {
			continue
		}
		id, err := transparencyLogID(b, rekorLogs, timestamp.URI, timestamp.Timestamp)
		if err != nil {
			return nil, err
		}
		result.TransparencyLogs = append(result.TransparencyLogs, TransparencyLog{
			ID:             id,
			URI:            timestamp.URI,
			IntegratedTime: timestamp.Timestamp,
		})
	}
	if verified.Statement == nil {
		return result, nil
	}

	result.PredicateType = verified.Statement.PredicateType
	for _, subject := range verified.Statement.Subject {
		digest := make(map[string]string, len(subject.Digest))
		for algorithm, value := range subject.Digest {
			digest[algorithm] = value
		}
		result.Subjects = append(result.Subjects, Subject{
			Name:   subject.Name,
			URI:    subject.Uri,
			Digest: digest,
		})
	}

	envelope, err := b.Envelope()
	if err != nil {
		return nil, err
	}
	statement, err := envelope.DecodeB64Payload()
	if err != nil {
		return nil, err
	}
	var raw struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(statement, &raw); err != nil {
		return nil, err
	}
	result.Statement = append(json.RawMessage(nil), statement...)
	result.Predicate = append(json.RawMessage(nil), raw.Predicate...)
	return result, nil
}

func transparencyLogID(b *bundle.Bundle, logs map[string]*root.TransparencyLog, uri string, integratedTime time.Time) (string, error) {
	entries, err := b.TlogEntries()
	if err != nil {
		return "", err
	}
	var found string
	for _, entry := range entries {
		id := hex.EncodeToString([]byte(entry.LogKeyID()))
		log, ok := logs[id]
		if !ok || log.BaseURL != uri || !entry.IntegratedTime().Equal(integratedTime) || !entry.HasInclusionPromise() {
			continue
		}
		if found != "" && found != id {
			return "", nil
		}
		found = id
	}
	return found, nil
}
