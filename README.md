# fount-broker

The broker is Fount's only route to the network. The Fount app is closed
source; this program is open so anyone can read exactly what can leave their
machine, and check that the binary shipped inside Fount was built from this
source.

The app runs the broker as a child process and names a destination from a fixed
list over stdin and stdout. It never passes a URL. The broker holds the
credentials, attests enclaves, and sends the request.

**The guarantee: your documents reach only an attested Tinfoil enclave, unless
they leave through one of the [channels below](#what-the-app-could-still-send).**

## What it allows

Everything the broker can reach is in [`internal/policy`](internal/policy/policy.go)
and can't change at runtime. A body that breaks its destination's rule is
refused before anything is sent.

| Destination | Goes to | Sealed |
|---|---|---|
| `tinfoil.chat_completions` | Fount's proxy, to an attested Tinfoil router | yes |
| `tinfoil.websearch`, `tinfoil.webfetch` | Fount's proxy, to Tinfoil's attested web enclave, then Exa | to the enclave |
| `openrouter.chat_completions` | Fount's proxy, to OpenRouter | no |
| `openrouter_byok.chat_completions` | OpenRouter, with the user's key | no |
| `fount.license_validate`, `fount.feedback_report` | `api.fount.sh` | no |
| `models.*`, `vision.*`, `latex.index` | S3, Hugging Face and the Tectonic bundle host, pinned by SHA-256 | no body |
| `latex.file` | The Tectonic bundle host, one file's byte range from the embedded index | no body |
| `updates.*` | Fount's GitHub releases. Fount verifies each package's signature, not the broker | no body |

Fount's proxy sees the metadata and ciphertext size of a sealed request, not
its contents. Tinfoil enclaves are verified with
[`tinfoil-go`](https://github.com/tinfoilsh/tinfoil-go) (V3 attestation, AMD
SEV-SNP or Intel TDX), and bodies are sealed to the attested key with
[EHBP](https://docs.tinfoil.sh/resources/ehbp).

Redirects are followed only for `updates` and `vision` GETs, and only to
GitHub's release hosts or Hugging Face's CDN.

uv can't speak the broker's protocol, so the broker also runs a password-protected
proxy on `127.0.0.1` ([`internal/proxy`](internal/proxy/proxy.go)). It opens
CONNECT tunnels on port 443 to the hosts in
[`python.go`](internal/policy/python.go) and nothing else.

## What the app could still send

The broker limits where requests go. It can't tell whether you asked for a
request. If the closed app were malicious, these are the channels it could use:

| Channel | Who can read it | What the app chooses |
|---|---|---|
| `tinfoil.webfetch` | Exa and each site | Up to 20 `https` URLs per call; a path or query can carry anything. No PII filter |
| `tinfoil.websearch` | Exa, after a best-effort PII filter | The search arguments, up to 16 KiB |
| `openrouter.chat_completions`, `openrouter_byok.chat_completions` | OpenRouter and the model provider | The whole request |
| `fount.feedback_report` | Fount | Up to 2 MiB, including free text. The app draws the preview you see |
| Python package tunnel | PyPI, GitHub | Paths on those hosts. `github.com` serves any repository, so a path can carry data |
| `fount.license_validate` | Fount | 64 characters of key per request |
| `latex.file` | The bundle's host | Which of about 130,000 files it asks for, and in what order |

Exa's zero-data-retention terms are a contract, not something the broker can
check. The PII filter and prompt-injection headers aren't sealed, so Fount's
proxy could remove them. Checking that the app uses these channels only when you
ask needs the app's source, which an audit covers, or an operating system
sandbox around the app, which is planned.

## Build

```sh
go test -race ./...
scripts/build-release.sh v0.0.0   # writes dist/
```

`-tags dev` builds a binary that honours `FOUNT_BROKER_PROXY` and
`FOUNT_BROKER_FOUNT_API`. Release builds don't contain that code. The wire
format is in [`internal/protocol`](internal/protocol/protocol.go).

## Verifying the broker in your copy of Fount

Each `v*` tag runs [`release.yml`](.github/workflows/release.yml), and Fount
bundles the release binary as it is. Check that it came from that workflow:

```sh
gh attestation verify /Applications/Fount.app/Contents/MacOS/fount-broker \
  --repo fount-labs/fount-broker
```

Builds are reproducible, so rebuilding at the tag gives the same bytes:

```sh
git checkout vX.Y.Z
scripts/build-release.sh vX.Y.Z   # compare with the release's SHA256SUMS
scripts/compare-signed.py /Applications/Fount.app/Contents/MacOS/fount-broker \
  dist/fount-broker-aarch64-apple-darwin
```

`compare-signed.py` checks that the signed binary is the release's `.unsigned`
build plus a signature and nothing else.

## License

Apache-2.0.
