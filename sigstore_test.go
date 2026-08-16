package sigstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

const testArtifactDigest = "46d4e2f74c4877316640000a6fdf8a8b59f1e0847667973e9859f774dd31b8f1e0937813b777fb66a2ac67d50540fe34640966eee9fc2ccca387082b4c85cd3c"

func TestVerifyBundleDetailed(t *testing.T) {
	body := testBundle(t)
	digest, err := hex.DecodeString(testArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}

	v := testVerifier(t)
	result, err := v.VerifyBundleDetailed(context.Background(), body, "sha512", digest)
	if err != nil {
		t.Fatalf("VerifyBundleDetailed: %v", err)
	}
	if result.CertificateIdentity != "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main" {
		t.Errorf("CertificateIdentity = %q", result.CertificateIdentity)
	}
	if result.CertificateIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("CertificateIssuer = %q", result.CertificateIssuer)
	}
	if len(result.TransparencyLogs) != 1 {
		t.Fatalf("len(TransparencyLogs) = %d, want 1", len(result.TransparencyLogs))
	}
	if result.TransparencyLogs[0].ID != "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d" {
		t.Errorf("TransparencyLogs[0].ID = %q", result.TransparencyLogs[0].ID)
	}
	if result.TransparencyLogs[0].URI != "https://rekor.sigstore.dev" {
		t.Errorf("TransparencyLogs[0].URI = %q", result.TransparencyLogs[0].URI)
	}
	if want := time.Unix(1692374735, 0); !result.TransparencyLogs[0].IntegratedTime.Equal(want) {
		t.Errorf("TransparencyLogs[0].IntegratedTime = %v, want %v", result.TransparencyLogs[0].IntegratedTime, want)
	}
	if result.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("PredicateType = %q", result.PredicateType)
	}
	if len(result.Subjects) != 1 {
		t.Fatalf("len(Subjects) = %d, want 1", len(result.Subjects))
	}
	if result.Subjects[0].Name != "pkg:npm/sigstore@2.0.0" {
		t.Errorf("Subjects[0].Name = %q", result.Subjects[0].Name)
	}
	if result.Subjects[0].Digest["sha512"] != testArtifactDigest {
		t.Errorf("Subjects[0].Digest[sha512] = %q", result.Subjects[0].Digest["sha512"])
	}

	var rawBundle struct {
		DSSEEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(body, &rawBundle); err != nil {
		t.Fatal(err)
	}
	statement, err := base64.StdEncoding.DecodeString(rawBundle.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Statement, statement) {
		t.Error("Statement does not contain the signed DSSE payload")
	}
	var predicate struct {
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
	}
	if err := json.Unmarshal(result.Predicate, &predicate); err != nil {
		t.Fatalf("decode Predicate: %v", err)
	}
	if predicate.RunDetails.Builder.ID != "https://github.com/actions/runner/github-hosted" {
		t.Errorf("predicate builder ID = %q", predicate.RunDetails.Builder.ID)
	}

	if err := v.VerifyBundle(context.Background(), body, "sha512", digest); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

func TestVerifyBundleDetailedReturnsNoMetadataOnFailure(t *testing.T) {
	body := testBundle(t)
	digest, err := hex.DecodeString(testArtifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	badDigest := append([]byte(nil), digest...)
	badDigest[0] ^= 0xff

	tests := []struct {
		name   string
		body   []byte
		digest []byte
	}{
		{name: "malformed bundle", body: []byte("{not-json"), digest: digest},
		{name: "unverified artifact digest", body: body, digest: badDigest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := testVerifier(t)
			result, err := v.VerifyBundleDetailed(context.Background(), test.body, "sha512", test.digest)
			if err == nil {
				t.Fatal("VerifyBundleDetailed returned no error")
			}
			if result != nil {
				t.Errorf("VerifyBundleDetailed returned metadata on failure: %#v", result)
			}
		})
	}
}

func testBundle(t *testing.T) []byte {
	t.Helper()
	body, err := os.ReadFile("testdata/sigstore-js-provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func testVerifier(t *testing.T) *Verifier {
	t.Helper()
	trustedRoot, err := root.NewTrustedRootFromPath("testdata/public-good-trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	return New(trustedRoot)
}
