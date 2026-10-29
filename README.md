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
| `tinfoil.websearch` | `POST https://api.fount.sh/proxy/mcp`, sealed to Tinfoil's attested web-search enclave | license | one MCP `search` call, encrypted |
| `tinfoil.webfetch` | the same, for the enclave's fetch tool | license | one MCP `fetch` call of 1 to 20 `https` URLs without user info, encrypted |
| `openrouter.chat_completions` | `POST https://api.fount.sh/proxy/openrouter/v1/chat/completions` | license | chat request |
| `openrouter_byok.chat_completions` | `POST https://openrouter.ai/api/v1/chat/completions` | the user's OpenRouter key | chat request |
| `fount.license_validate` | `POST https://api.fount.sh/license/validate` | none | `licenseKey` only |
| `fount.feedback_report` | `POST https://api.fount.sh/feedback/v1/report` | none | the report's fields only, 2 MiB at most |
| `models.<model>/<file>` | `GET https://fount-embedding-models.s3.us-east-1.amazonaws.com/models/<model>/<file>` | none | none; the file must match its SHA-256 in [`models.go`](internal/policy/models.go) |
| `vision.<repo>/<file>` | `GET https://huggingface.co/<repo>/resolve/<revision>/<file>` | none | none; the revision and the file's SHA-256 are pinned in [`vision.go`](internal/policy/vision.go) |
| `updates.manifest` | `GET https://github.com/fount-labs/fount/releases/latest/download/latest.json` | none | none |
| `updates.package` | `GET https://github.com/fount-labs/fount/releases/download/v<version>/Fount_<version>_<package>`, the package for macOS or Windows | none | none |

A body that breaks its destination's rule is refused before anything is sent.
The app names a destination; only `updates.package` also takes a path, and
[`updates.go`](internal/policy/updates.go) says which. Redirects are followed
only for the `updates` and `vision` destinations, only for GETs, and only to
GitHub's release hosts or Hugging Face's CDN; any other redirect is returned to the app unfollowed.
The broker doesn't check update signatures: Fount verifies each package
against the updater key compiled into it before installing.
OpenRouter requests aren't sealed, whether Fount hosts them or the user brings
their own key: OpenRouter and the model provider can read them. Only Tinfoil requests are private from everyone but
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

### Tinfoil web search

Web search goes the same way, sealed to `websearch.tinfoil.sh`, which must be
built from
[`tinfoilsh/confidential-websearch`](https://github.com/tinfoilsh/confidential-websearch).
The broker always asks the enclave to run its PII filter on the query.

Search is less private than inference. The enclave sends the query to
[Exa](https://exa.ai), which can read it. The PII filter removes the
sensitive values it detects first, but it can miss some. Exa doesn't keep
the query under its zero-data-retention terms, but that's a contract, not
something the broker can check. Exa never sees your IP address. The PII
filter header isn't sealed, so Fount's proxy could remove it.

### Tinfoil web fetch

Fetch goes to the same enclave. The enclave asks Exa for each page's text:
Exa's crawler visits the page, or Exa serves a copy up to two hours old, so
the site sees Exa, not you. Exa and the site see the URL as it is; the enclave
doesn't run its PII filter on fetches. The broker always asks the enclave to
check each page for prompt injection. Like the PII header, that header isn't
sealed.

### Python packages

uv, the package manager Fount uses for Python, can't speak the broker's
protocol, so the broker also runs a proxy on `127.0.0.1`
([`internal/proxy`](internal/proxy/proxy.go)). It opens CONNECT tunnels to
the hosts in [`python.go`](internal/policy/python.go), on port 443 only:

- `pypi.org` and `files.pythonhosted.org`, for packages
- `github.com`, `release-assets.githubusercontent.com` and
  `objects.githubusercontent.com`, for Python itself (python-build-standalone)

It refuses every other host and anything that isn't a CONNECT. TLS runs end
to end between uv and the host, so the broker sees only the host name and the
byte counts, and can't limit which paths on those hosts are fetched. The
proxy's password is made at each launch and sent to the app in the `ready`
frame, so other local programs can't use it. On macOS Fount runs uv in a
sandbox where loopback is its only network, so the tunnel is its only way out.

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
