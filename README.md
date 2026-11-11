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
| `tinfoil.convert_file` | Fount's proxy, to an attested Tinfoil router, then Tinfoil's document enclave. Up to 16 MiB of PDF pages for OCR | yes |
| `tinfoil.websearch`, `tinfoil.webfetch` | Fount's proxy, to Tinfoil's attested web enclave, then Exa | to the enclave |
| `openrouter.chat_completions` | Fount's proxy, to OpenRouter | no |
| `openrouter_byok.chat_completions` | OpenRouter, with the user's key | no |
| `fount.license_validate`, `fount.feedback_report` | `api.fount.sh` | no |
| `models.*`, `vision.*`, `latex.index` | S3, Hugging Face and the Tectonic bundle host, pinned by SHA-256 | no body |
| `latex.file` | The Tectonic bundle host, one file's byte range from the embedded index | no body |
| `updates.*` | Fount's GitHub releases. Fount verifies each package's signature, not the broker | no body |
| `mail` requests | The Fount Mail edge, an attested Tinfoil enclave. See [Mail](#mail) | TLS to the attested key |

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
| Mail writes (`mailbox`, `address`, `routing`, `renew`) | The edge enclave, and its storage for what it keeps | Up to 64 KiB of signed JSON. The edge refuses anything that isn't a valid request |
| `latex.file` | The bundle's host | Which of about 130,000 files it asks for, and in what order |
| Mail sender checks | Google and Cloudflare DNS | Nothing. The verifier asks for the DKIM, DMARC and SPF records of mail you received, at most 48 questions per message. Senders choose those names |

Exa's zero-data-retention terms are a contract, not something the broker can
check. The PII filter and prompt-injection headers aren't sealed, so Fount's
proxy could remove them. Checking that the app uses these channels only when you
ask needs the app's source, which an audit covers, or an operating system
sandbox around the app, which is planned.

## Mail

The broker is the device's side of Fount Mail
([`internal/mail`](internal/mail/service.go)). The app gives it each address's
keys once, as the `mail_keys` credential, and then names an operation and a
mailbox: `list`, `get`, `delete`, `gaps`, and `ledger` and `restore` for the
sequence ledger. The broker signs each of these reads with the address's key,
so the app never builds one. Writes are different; see the end of this section.

For each message it:

1. Checks the edge's signature against the boot that signed it, from
   `GET /boots/:id`. A boot whose key the edge's live attestation endorses is
   marked attested. An older boot's key comes only from storage, and the
   message says so.
2. Refuses a message for another mailbox or sealed to a key the device doesn't
   hold, and decrypts the rest (HPKE from Go's standard library).
3. Records its sequence number. With the edge's signed gap records, every
   number must be a message, an expired message or a voided one. A number
   that's none of these is withheld mail, and one used twice is an anomaly.
4. Runs the sender verifier on it.

The verifier ([`internal/mail/verify`](internal/mail/verify/check.go)) is this
binary run as `fount-broker mail-verify`, a fresh process for each message,
with no keys and an empty environment. On macOS it runs under `sandbox-exec`
with no network and no files beyond the system libraries. On Windows and Linux
it isn't confined yet. It parses the headers, checks DKIM, DMARC and SPF, and
gets DNS answers only by asking the broker, which fetches them from both
resolvers above and passes them back unread. The two must agree. A crash or
timeout fails the check, and after three failures the message is quarantined.

SPF checks the sending server's address and HELO name, which the edge seals
with each message from stored-message format 2. The edge reads that address
from the PROXY header its gateway writes, and nothing attests the gateway, so
an SPF result is only as honest as the gateway. The verdict says so: `spf`
carries the `client_ip` it checked and `client_ip_source: "gateway_proxy"`.
Mail with no recorded address (format 1, or format 2 without one) reports SPF
`none`. The automatic-request rule needs strict DKIM alignment, not SPF.

The app signs its own writes, which carry only public keys, and the broker
carries them unchanged ([`mail/passthrough.go`](internal/mail/passthrough.go)).
Each op has a fixed method and path, because the signature covers both:

| Op | Sends | `mailbox` |
|---|---|---|
| `handle` | `GET /handle/{path}`, `path` matching `^[a-z0-9-]{1,64}$` | empty |
| `mailbox` | `POST /mailbox` | empty |
| `address` | `POST /address` | the parent mailbox |
| `routing` | `PUT /routing` | the mailbox |
| `renew` | `POST /entitlement` | the mailbox |
| `license_entitlement` | `api.fount.sh` `POST license/entitlement` | empty |

The frame's `headers` may hold only `Fount-Key-Id`, `Fount-Timestamp`,
`Fount-Nonce`, `Fount-Signature` and `Fount-Entitlement`, and `Fount-Key-Id`
must equal `mailbox`. Edge ops go only to the attested edge. For
`license_entitlement` the app sends `{"deviceKey":"<base64>"}` and the broker
adds the `license` credential it holds. Every op answers with a result
`{"status":N,"body":<reply JSON>,"retry_after":N}`, 4xx included; an `error`
frame means the broker itself failed. Bodies and replies are capped at 64 KiB.

## Parse surfaces

Every place the broker parses bytes it didn't make. Each is bounded and fails
closed.

In the broker:

| Input | From | Code |
|---|---|---|
| Frames and request headers | The app | [`frame`](internal/frame/frame.go), [`protocol`](internal/protocol/protocol.go) |
| Request bodies with a schema | The app | [`policy/body.go`](internal/policy/body.go) |
| Mail write frames: signature headers, handle names, `deviceKey` | The app | [`mail/passthrough.go`](internal/mail/passthrough.go) |
| `mail_keys` and saved ledgers | The app | [`mail/keys.go`](internal/mail/keys.go), [`mail/service.go`](internal/mail/service.go) |
| CONNECT requests | Local processes with the tunnel password | [`proxy`](internal/proxy/proxy.go) |
| Attestation documents | Tinfoil enclaves | `tinfoil-go` |
| HTTP responses | Every destination. Bodies are streamed to the app unread | `net/http` |
| Device API JSON: listings, gap pages, boot records. Write replies are only checked to be JSON, then passed to the app | The edge | [`mail/edge.go`](internal/mail/edge.go) |
| Stored messages and gap records, checked against a boot's key | The edge and its storage | [`mail/object.go`](internal/mail/object.go), [`mail/record.go`](internal/mail/record.go) |
| The verifier's frames | The verifier | [`mail/verify/process.go`](internal/mail/verify/process.go) |

In the verifier, which holds nothing worth taking:

| Input | From | Code |
|---|---|---|
| Message headers, `From`, address lists, encoded words | Senders | [`verify/check.go`](internal/mail/verify/check.go), `net/mail`, `mime` |
| DKIM signatures and key records, DMARC records, SPF records | Senders and their DNS | `go-msgauth`, `blitiri.com.ar/go/spf` |
| DNS responses | The two resolvers | `golang.org/x/net/dns/dnsmessage` |

## Build

```sh
go test -race ./...
scripts/build-release.sh v0.0.0   # writes dist/
```

`-tags dev` builds a binary that honours `FOUNT_BROKER_PROXY`,
`FOUNT_BROKER_FOUNT_API` and `FOUNT_BROKER_MAIL_EDGE`. Release builds don't contain that code. The wire
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
