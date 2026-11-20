# Coordinator backups and restores

The coordinator backs its volume up to a versioned S3 bucket and can restore
one onto a fresh volume (fount `launch-plan.md`, "Durable storage" and
decisions 15 to 18). The code is `internal/coordinator/backup*.go` and
`restore.go`; the bucket client is `internal/s3bucket`; the flags are in
`cmd/fount-coordinator/backup.go`.

## What is wired, and what isn't

| Piece | State |
|---|---|
| Backups, the security counter, restore, export | Built in `internal/coordinator` |
| S3 bucket client (`internal/s3bucket`) | Built: SigV4, write-once `Put`, paged `List`, through the S3 forwarder |
| `--backup-bucket`, `--restore`, `--restore-dry-run` | Built, with `--wrapping-key dev` and `--dev-vault`, or `--wrapping-key vault` and `--coordinator-authority-key` |
| The Cloud vault's generation and counter | Built in fount-mail-vault (`COORDINATOR_MODE`, `docs/COORDINATOR-COUNTER.md`); the coordinator's side is `vaultkey` (the boot) and `coordinator.WireCounter`. Not yet run against a deployed Cloud vault pair |
| Backups under `--wrapping-key vault` | Need `--coordinator-authority-key`. The bucket's credentials come from the vault, never from `$AWS_*` |

With `--wrapping-key vault --coordinator-authority-key <key>`, the key is the
Cloud vaults' `GENERATION_AUTHORITY_KEY`, the same string the edge has as
`COORDINATOR_AUTHORITY_KEY`. Every boot's keyset pull then boots a
generation: the coordinator attests to a fresh per-boot Ed25519 key, and the
vault answers a certificate for it under that authority, once both vaults
hold the new generation. That fences every coordinator before it, at the
vault's counter and at the edge. `--restore-dry-run` pulls without booting.
`--mail` with the vault's key needs the authority key too.

`--dev-vault <file>` stands in for the vault: a file holding the generation
and the count (`coordinator.FileVault`). Each boot moves the generation on and
keeps the count, as the vault will. Its generation certificates are signed by
`--mail-generation-authority`'s seed, or a seed made next to the file
(`<file>.authority`), and the log names the public key, which a dev edge takes
as `COORDINATOR_AUTHORITY_KEY`. With `--mail`, mail runs under the same
generation. Keep the file off the volume. A restore drill wipes the volume,
and if the counter goes with it, nothing a restore takes can be refused as
rolled back.

## Flags

| Flag (env) | Meaning |
|---|---|
| `--backup-bucket` (`FOUNT_BACKUP_BUCKET`) | The bucket's endpoint, `https://<bucket>.s3.<region>.amazonaws.com`. Turns backups on |
| `--backup-region` (`FOUNT_BACKUP_REGION`) | Its region |
| `--backup-forwarder` (`FOUNT_BACKUP_FORWARDER`) | `host:port` of the S3 forwarder in an enclave. TCP goes there, and TLS still runs to S3 and checks its certificate |
| `--backup-interval` | How often a changed volume is backed up. Default 5m. Every security change is also backed up and counted before it's acknowledged |
| `--backup-retention` | How long roots are kept: every one from the last day, then one a day. Default 30 days, at most 80 (`MaxRestoreAge`) |
| `--backup-delete-mail` | Delete mail from the edge once every backup a restore could take has acted on it. Off by default, so the edge keeps it |
| `--dev-vault` | The vault stand-in file, required with `--wrapping-key dev` |
| `--coordinator-authority-key` (`FOUNT_COORDINATOR_AUTHORITY_KEY`) | With `--wrapping-key vault`: the Cloud vaults' `GENERATION_AUTHORITY_KEY`. Required for backups and for `--mail` |
| `--restore latest\|roots/<key>` | Restore onto an empty `--dir` before serving |
| `--restore-dry-run` | With `--restore`: check the backup and write nothing |

With `--wrapping-key dev`, credentials come from `$AWS_ACCESS_KEY_ID`,
`$AWS_SECRET_ACCESS_KEY`, and `$AWS_SESSION_TOKEN` for temporary credentials.
With `--wrapping-key vault` they come from the vault, and a `$AWS_*` in the
environment is refused.

Bucket layout: `objects/<worker>/<object>`, each a tree object already sealed
under its worker's DEK, and `roots/<generation>-<seq>-<unix>`, each sealed
under a key derived from the wrapping key. The bucket sees ciphertext and
sizes only. Every `Put` is `If-None-Match: *`, with S3 checking a SHA-256 of
the body. An object is written whole or not at all and is never replaced. A
retry that meets its own bytes succeeds; other bytes are an error.

## Restoring

`Restore` refuses:
- a backup below the vault's counter, which would roll back security state;
- one older than 80 days, past what the edge's sent records answer for;
- a volume that already has state;
- a generation the vault has moved past;
- a backup that doesn't open under the wrapping key, or has any object missing.

1. **Dry run.** Start the coordinator on an empty `--dir` with
   `--restore latest --restore-dry-run`, or name a root. It opens the root and
   every worker's tree, and reads every file from the bucket. It doesn't move
   the vault's generation, so the coordinator running now keeps running. It
   logs `restore: {"root":…,"takenAt":…,"securitySeq":…,"workers":…,"objects":…,"stoppedJobs":…,"dryRun":true}`,
   then serves nothing until stopped. In an enclave, a restart doesn't repeat
   the check.
2. **Restore.** Start it on an empty volume with `--restore latest`, or the
   root the dry run named. It restores under a new generation, which fences
   the old coordinator at the vault and at the edge, then serves. Jobs queued
   or running at the backup are failed. Mail the restored ledgers lack is held
   for a person. A send in flight resumes by asking the edge first.
3. **Take `--restore` off** in the next config. Leaving it on is harmless
   while the volume holds the restore: a restart logs "the volume was restored
   from …" and serves. But on a later empty volume it would restore again by
   itself. On a volume nothing was restored onto, `--restore` refuses to start.

With `--wrapping-key dev`, copy the dev key the backups were taken under to
`<dir>/wrapping.key` first. A new one would be made otherwise, and no backup
opens under it, so `--restore` refuses to start without the file.

### Dev, against any S3 that honours `If-None-Match` on PUT

```sh
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…
fount-coordinator --dir /tmp/c1 --wrapping-key dev --dev-vault /tmp/dev-vault.json \
  --backup-bucket https://<bucket>.s3.us-east-1.amazonaws.com --backup-region us-east-1 -- scripts/dev-runner.sh
# the drill: lose the volume, keep the key and the vault
mkdir /tmp/c2 && cp /tmp/c1/wrapping.key /tmp/c2/
fount-coordinator --dir /tmp/c2 … --restore latest --restore-dry-run
fount-coordinator --dir /tmp/c2 … --restore latest -- scripts/dev-runner.sh
```

## Infrastructure checklist (the user creates these; nothing here creates them)

**Egress.** Tinfoil's allowlist reaches S3 about 1 time in 30, because it
snapshots one DNS answer while S3's addresses rotate. Through a forwarder
container on an `open` network, a real enclave reached S3 on 1,965 of 1,968
tries; the 3 failures were at startup. That was the mail edge's 32-minute
probe (`tinfoil-s3-egress-probe`, fount-mail-design.md §6, fount-mail-gaps.md
1.10). The coordinator does the same:

- [ ] In the coordinator's `tinfoil-config.yml`, add `internal: {}` and
      `storage: {egress: open}` networks. The coordinator joins `internal`
      next to `coordinator-out`.
- [ ] Add a `forwarder` container on `[internal, storage]` running the mail
      edge's image, pinned by digest, with `command: ["egress-forward"]`,
      `restart: always` and
      `EGRESS_ROUTES: "9001=<bucket>.s3.<region>.amazonaws.com"`. It holds no
      secret, needs no attestation, and relays TLS bytes it can't read. The
      edge image's healthcheck reads the edge's config, so check it works for
      a forwarder alone, or leave it out.
- [ ] Give the coordinator `--backup-forwarder forwarder:9001`, plus
      `--backup-bucket` and `--backup-region`.
- [ ] Before production, run a live check from the coordinator enclave: a
      backup, a dry run, then a restore. The probe only ran from the mail
      edge's enclave.

**Bucket** (one per coordinator deployment, in the mail buckets' region,
`us-east-1`):

- [ ] Name it like `fount-coordinator-backup-<account id>`.
- [ ] Turn Block Public Access on (all four), with Object Ownership "bucket
      owner enforced" (ACLs off) and default encryption SSE-S3. The objects
      are sealed already, so this is belt and braces.
- [ ] Turn versioning on. Don't use Object Lock: a retention period would
      keep versions past the 80-day window.
- [ ] Add a lifecycle rule on the whole bucket:
      `NoncurrentVersionExpiration.NoncurrentDays = 45`,
      `ExpiredObjectDeleteMarker = true` and
      `AbortIncompleteMultipartUpload.DaysAfterInitiation = 1`. Keep
      `--backup-retention` plus `NoncurrentDays` under 80 days, with margin
      because S3 expires asynchronously: 30 + 45 = 75. A root then can't be
      read back once it is older than `MaxRestoreAge`, which is 80 days, under
      the edge's 90 days of sent records. Restore also refuses anything older
      by the sealed `takenAt`, so the rule is the second line, and it means
      deleted data really goes.
- [ ] Add a bucket policy:
  - deny `s3:*` when `aws:SecureTransport` is false;
  - deny `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`,
    `s3:GetObjectVersion` and `s3:DeleteObjectVersion` on `arn:aws:s3:::<bucket>/*` to every principal
    whose `aws:PrincipalArn` isn't the coordinator's IAM user.

**IAM:**

- [ ] Create the IAM user `fount-coordinator-backup`, with no console access
      and one access key.
- [ ] Give it this policy and nothing else:
  - `s3:PutObject`, `s3:GetObject` and `s3:DeleteObject` on
    `arn:aws:s3:::<bucket>/*`;
  - `s3:ListBucket` on `arn:aws:s3:::<bucket>`. Without it, S3 answers 403
    instead of 404 for a missing key, and `Get` would fail instead of
    reporting `ErrNotFound`.
  - No version, lifecycle, versioning or policy actions. The coordinator
    can't read old versions or purge the history.
- [ ] Keep no copy of the secret key once it's delivered below. Rotate it by
      making a second key, delivering it, then deleting the first.

**Getting the credentials into the enclave:**

- [ ] *Test coordinator* (`--wrapping-key dev`, test data only): declare
      `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` as Tinfoil `secrets:` on
      the coordinator container, and set them in Tinfoil.
- [ ] *Production* (`--wrapping-key vault`): import the key into the Cloud
      vault pair with `vaultctl import-s3`, signed by the operator key. The
      vault already seals S3 credentials into the keyset it releases to an
      attested coordinator release (`wire.Payload.S3`). The Cloud vault pair
      is separate from the mail vaults, so its S3 slot is free.
      `vaultkey.Fetch` keeps them and the bucket client uses them, so no
      Tinfoil secret and no deploy config holds them.
- [ ] Residual risk, to state publicly: AWS account admins can always mint
      credentials and change the bucket policy. The bucket only ever sees
      ciphertext. Rollback is stopped by the vault's counter and the sealed
      `takenAt`, not by IAM.

## What needs a live test

- S3 from the coordinator enclave through the forwarder: `Put`,
  `If-None-Match` (412 and 409 answers), paged `List`, a 404 that is a 404
  under the IAM policy, and the lifecycle rule actually expiring noncurrent
  versions.
- The restore drill on the test coordinator: back up, wipe the volume, dry
  run, restore, with a send in flight and an edge reboot between (launch
  de-risk 2).
- Against a deployed Cloud vault pair (`COORDINATOR_MODE`): a boot's
  certificate taken by the edge; a restore below the counter refused; an
  old-generation coordinator fenced at the counter and the edge; backups
  under the vault's S3 credentials; one vault down holding changes back
  (`ErrNotDurable`) without retiring the coordinator.
