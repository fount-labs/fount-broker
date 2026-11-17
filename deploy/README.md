# Enclave configs (drafts)

Not deployed. `runner/tinfoil-config.yml` is a runner enclave as m4-cloud-runners.md
§5.1c describes it. Its placeholders are listed at the top of the file.

The coordinator enclave isn't built yet; it waits on P2 (dev API, dev wrapping key). Its
config will need:

```yaml
attested-keys:
  - id: fount-link    # its end of the link to runners
    key: ed25519
  - id: job-signing   # signs each job's credential; the proxy learns it from the attestation
    key: ed25519

containers:
  - name: coordinator
    keys: [fount-link, job-signing]
    attestation: true
    env:
      - FOUNT_RUNNER_REPO: "<the runner config repo>"   # --runner-repo
```

The proxy can't yet check a `job-signing` key from an attestation:
`@tinfoilsh/verifier` (1.4.0 at most) has no V3 or `crypto_material`. Until it does, or
until the proxy calls a Go verifier, the proxy is configured with the key by hand
(`JOB_CREDENTIAL_PUBLIC_KEYS`), and every coordinator reboot changes it.

The link probe (`~/Desktop/code/link-probe`) checks both enclaves' part on live Tinfoil:
the upgrade through the shim, the handshake, and fetching a peer's attested key from its
public shim.
