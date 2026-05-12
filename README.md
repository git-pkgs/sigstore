# sigstore

A thin `sigstore-go` wrapper that validates a sigstore bundle against the live (or cached) Sigstore TUF trust root. Cross-ecosystem by design: handles any `(digestAlg, digest)` pair, so npm tarball (`sha512`), GitHub artifact (`sha256`), PyPI distribution, Maven Central, and Cargo package attestations all use the same code path.

## Install

```
go get github.com/git-pkgs/sigstore
```

## Usage

```go
import (
    "crypto/sha512"

    "github.com/sigstore/sigstore-go/pkg/root"

    "github.com/git-pkgs/sigstore"
)

tr, err := root.FetchTrustedRoot() // or FetchTrustedRootWithOptions for a local cache
if err != nil { return err }

v := sigstore.New(tr)
digest := sha512.Sum512(artifactBytes)
err = v.VerifyBundle(ctx, bundleBytes, "sha512", digest[:])
```

`VerifyBundle` returns nil when:

- the bundle's Fulcio cert chains to the trust root,
- the Rekor inclusion proof is valid,
- the DSSE envelope signature matches the cert,
- the in-toto subject digest matches the supplied `(digestAlg, digest)`.

## Pluggable verifier pattern

Consumers typically declare a one-method interface so other verifiers (witness, SBOMit, plain in-toto) can swap in:

```go
type ProvenanceVerifier interface {
    VerifyBundle(ctx context.Context, body []byte, alg string, digest []byte) error
}
```

`*Verifier` satisfies this structurally — no shared interface package needed.

## Why standalone

`sigstore-go` is a heavy dependency (TUF, Fulcio, Rekor, x509, protobuf). Carrying it in larger surfaces (CLIs, libraries) is wasteful when consumers only want bundle verification. Importing this package opts in explicitly.

For identity-field extraction without verification, see [`github.com/git-pkgs/attestation`](https://github.com/git-pkgs/attestation) (stdlib-only).

## License

MIT
