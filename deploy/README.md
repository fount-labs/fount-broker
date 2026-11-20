# Enclave configs (drafts)

The broker and supervisor images come from `Dockerfile`, built and attested by the release workflow at each tag. `runner/tinfoil-config.yml` is a runner enclave as m4-cloud-runners.md
§5.1c describes it; the deployed copy is public `fount-labs/fount-cloud-runner` (v0.1.0 runs as `runner-a`). Its placeholders are listed at the top of the file.

`coordinator/tinfoil-config.yml` is the coordinator enclave, P2's first slice (m4-cloud-runners.md
§7): the coordinator image with attested `fount-link` and `job-signing` keys, sending jobs over
links runners dial in to it (`--runners-dial-in` on the client port's `/fount-link`; the runner's
`--coordinator`), so its allowlist names no runner, and a `fount-client` key for the attested client channel
(`--client-listen`), which takes dev fount-infra's Cloud credentials only. It also serves the dev
API behind a bearer token (`--test-api`, Tinfoil secret `FOUNT_TEST_API_TOKEN`) on the same port,
and its wrapping key is the dev one, so it handles test data only. The deployed copy is public
`fount-labs/fount-cloud-coordinator` (v0.3.2 runs as `coordinator-a`).

The proxy learns each boot's `job-signing` key from the coordinator's attestation
(fount-infra `proxy-server/coordinator-keys.ts`, `@tinfoilsh/verifier` 2.0.0-rc.2 pinned),
given `COORDINATOR_ORIGINS` and `COORDINATOR_REPO`. `JOB_CREDENTIAL_PUBLIC_KEYS` stays as
a manual override.

The link probe (`~/Desktop/code/link-probe`) checks both enclaves' part on live Tinfoil:
the upgrade through the shim, the handshake, and fetching a peer's attested key from its
public shim.

Backups to S3 need a forwarder container and an open network in the coordinator's
config, because Tinfoil's allowlist doesn't reach S3 reliably. The checklist is in
[docs/backups.md](../docs/backups.md).
