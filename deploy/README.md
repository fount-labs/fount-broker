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

The proxy learns each boot's `job-signing` key from the coordinator's attestation
(fount-infra `proxy-server/coordinator-keys.ts`, `@tinfoilsh/verifier` 2.0.0-rc.2 pinned),
given `COORDINATOR_ORIGINS` and `COORDINATOR_REPO`. `JOB_CREDENTIAL_PUBLIC_KEYS` stays as
a manual override.

The link probe (`~/Desktop/code/link-probe`) checks both enclaves' part on live Tinfoil:
the upgrade through the shim, the handshake, and fetching a peer's attested key from its
public shim.
