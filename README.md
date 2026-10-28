# fount-broker

The broker is Fount's only route to the network. The Fount app is closed
source; this program is open so anyone can read exactly what can leave their
machine, and check that the binary shipped inside Fount was built from this
source.

The app starts the broker as a child process and talks to it over stdin and
stdout. It names a destination from a fixed list. It never passes a URL. The
broker holds the credentials, attests enclaves, and sends the request.

## What it allows

Everything the broker can reach is in [`internal/policy`](internal/policy/policy.go).
Nothing there can change at runtime.

| Destination | Goes to | Credential | Body |
|---|---|---|---|
| `tinfoil.chat_completions` | `POST https://api.fount.sh/proxy/v1/chat/completions`, sealed to an attested Tinfoil router | license | chat request, encrypted |
| `openrouter.chat_completions` | `POST https://api.fount.sh/proxy/openrouter/v1/chat/completions` | license | chat request |
| `fount.license_validate` | `POST https://api.fount.sh/license/validate` | none | `licenseKey` only |
| `fount.feedback_report` | `POST https://api.fount.sh/feedback/v1/report` | none | the report's fields only, 2 MiB at most |
| `models.<model>/<file>` | `GET https://fount-embedding-models.s3.us-east-1.amazonaws.com/models/<model>/<file>` | none | none; the file must match its SHA-256 in [`models.go`](internal/policy/models.go) |

A body that breaks its destination's rule is refused before anything is sent.
Fount-hosted OpenRouter requests aren't sealed: OpenRouter and the model
provider can read them. Only Tinfoil requests are private from everyone but
the enclave.

### Tinfoil inference

Before it sends a request body, the broker verifies a Tinfoil router with
[`tinfoil-go`](https://github.com/tinfoilsh/tinfoil-go). Verification uses
V3 attestation: it is bound to a fresh nonce and checks freshness and
revocation, on AMD SEV-SNP or Intel TDX. The router must be built from
`tinfoilsh/confidential-model-router`.

Each body is sealed with [EHBP](https://docs.tinfoil.sh/resources/ehbp) to the
router's attested key, then sent through Fount's proxy. The proxy adds Fount's
Tinfoil key and meters usage. It sees the method, path, headers and the size of
the ciphertext. It can't see the prompt or the reply.

## Protocol

Each frame is a JSON header and an opaque body, and each part is prefixed by
its length as a big-endian `uint32`. The broker parses only the header.
Headers are decoded strictly: an unknown field, a field that doesn't belong to
the request kind, or trailing data rejects the request. See
[`internal/protocol`](internal/protocol/protocol.go).

## Build

```sh
go test -race ./...
scripts/build-release.sh v0.0.0   # writes dist/
```

`-tags dev` builds a binary that honours `FOUNT_BROKER_PROXY`, the origin of a
staging proxy, and `FOUNT_BROKER_FOUNT_API`, the base URL of a staging license
API. Release builds don't contain that code.

## Releases

Each `v*` tag runs [`release.yml`](.github/workflows/release.yml). It builds
every binary with `scripts/build-release.sh`, signs the macOS binary with
Fount's Developer ID, and publishes all of them with a
[build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations).
Fount bundles the release binary as it is. Fount's own signing doesn't touch
it.

### Verifying the broker in your copy of Fount

Check that it came from this repo's release workflow:

```sh
gh attestation verify /Applications/Fount.app/Contents/MacOS/fount-broker \
  --repo fount-labs/fount-broker
```

Check that the release was built from this source. Builds are reproducible,
so rebuilding at the tag gives the same bytes:

```sh
git checkout vX.Y.Z
scripts/build-release.sh vX.Y.Z   # compare with the release's SHA256SUMS
scripts/compare-signed.py /Applications/Fount.app/Contents/MacOS/fount-broker \
  dist/fount-broker-aarch64-apple-darwin
```

The macOS release also ships its unsigned build as
`fount-broker-aarch64-apple-darwin.unsigned`. `compare-signed.py` checks that
the signed binary is that build plus a signature and nothing else.

## License

Apache-2.0.
