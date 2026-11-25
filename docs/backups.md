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
| The restore drill (`scripts/restore-drill.sh`) | Built: the runbook end to end against an S3 stand-in and the vault's wire protocol, in the package and on the binary. See "Rehearsing a restore" |
| Backups under `--wrapping-key vault` | Need `--coordinator-authority-key`. The bucket's credentials come from the vault, never from `$AWS_*` |
| `GET /control/backup` | Built: when the last backup ran, succeeded and failed. See "Watching backups" |

With `--wrapping-key vault --coordinator-authority-key <key>`, the key is the
Cloud vaults' `GENERATION_AUTHORITY_KEY`, the same string the edge has as
`COORDINATOR_AUTHORITY_KEY`. Every boot then takes a generation: the
coordinator attests to a fresh per-boot Ed25519 key, proves it holds the
transfer key its document names (a MAC under the X25519 agreement with the
vault's, fount-mail-vault review C1), and the vault answers a certificate
for it under that authority, once both vaults hold the new generation. That
fences every coordinator before it, at the vault's counter and at the edge.

The generation waits for the volume. The keyset pull boots nothing; once the
volume is open, the coordinator boots only when its security sequence has
reached the vault's count, when the vault has counted nothing yet, or when
`--restore` is about to put a backup onto an empty volume. A blank disk, an
old copy or a create with no disk is refused: `/status` says `refused` with
why, and the coordinator serves `/status` alone until stopped, fencing
nobody. `--restore-dry-run` never boots. A coordinator a newer generation
retired answers `/health` with 503. `--mail` with the vault's key needs the
authority key too.

**A refusal fails the Tinfoil deploy.** A refused boot or volume answers
`/health` with 503, and the body is the reason: `refused: this volume may
not take a generation: <why>` or `refused: the volume didn't open: <why>`,
the same text as `/status`'s `last_error`, which holds no user data. The
container's healthcheck (`fount-coordinator health`) prints that body. On
Tinfoil a container that is unhealthy at boot fails its deploy, and the
instance is left Failed (for one with a volume, a failed update too), with
its DNS gone, so `/status` and `--status-listen` can't be reached. Read
why in the dashboard: a Failed instance's Deploy dialog shows the last
error, which is that healthcheck output. `tinfoil container list -o json`
lists the Failed instances. Fix what it names (attach the coordinator's
own volume, or `--restore` onto an empty one) and deploy again. Container
logs (`tindbg logs`) need a debug-mode build, so don't rely on them in
production.

With `--counter-states` (`FOUNT_COORDINATOR_COUNTER_STATES=1`) every count
is bound to the state it counts (counter version 2): a digest of the
security sequence, the generation that made it, and each team's log head and
rotation marks, with the counting generation as writer. A volume or backup
at the vault's count with another digest is a fork and is refused, as is a
volume one change ahead whose change is from a generation older than the
last writer. Only Cloud vaults with version 2 answer it, so turn it on once
both serve it. Without it the counter binds the number alone.

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
| `--counter-states` (`FOUNT_COORDINATOR_COUNTER_STATES=1`) | Counter version 2: bind each count to its state. Only once both Cloud vaults serve it |

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

## Watching backups

`GET /control/backup` is on the control route, with `/control/runners` and
`/control/mail`: it needs `$FOUNT_CONTROL_TOKEN` as a bearer token, so it is
there only with `--runners-dial-in` and `--team-runner-stage`. It answers 503
until the coordinator has its key. Without backups it answers
`{"backup":{"configured":false}}`, not 404, since a production coordinator
without them is the thing to catch. With them:

```json
{"backup": {
  "configured": true,
  "generation": 2,
  "interval_seconds": 300,
  "last_attempt_at": "2026-11-24T18:05:00Z",
  "last_success_at": "2026-11-24T18:00:00Z",
  "last_error": "writing backup roots/...: s3: put \"roots/...\": 403 Forbidden: AccessDenied: Access Denied",
  "last_error_at": "2026-11-24T18:05:01Z",
  "last_root": "roots/00000000000000000002-00000000000000000041-00000000001764007200",
  "last_root_at": "2026-11-24T18:00:00Z",
  "last_run": {"objects": 3, "bytes": 18211}
}}
```

- `last_attempt_at`: a backup started, on the timer or for a security change.
- `last_success_at`: the bucket last held the volume as it was, by a new root
  or by finding the volume unchanged. On an idle volume it moves every
  interval while `last_root_at` stays put. A `last_success_at` more than a
  couple of intervals old, or older than `last_error_at`, means backups are
  failing.
- `last_error`: the latest failed backup, failed read of the vault's counter
  on the timer, or failed retention pass, with what failed in front. It is
  scrubbed before it leaves the enclave: anything shaped like an AWS key id,
  and any run of base64 longer than an id, reads `[redacted]`. It names roots
  and objects by key, as a bucket listing would, and can name a worker.
- `last_run`: what writing `last_root` put in the bucket, the tree objects the
  bucket didn't have yet and the bytes of those and the root.
- `stopped`: why this coordinator stopped backing up, once a newer generation
  took over.

The status is in memory: a restart starts empty and fills in with the backup
it takes at boot. The bucket name, credentials and contents are never in it.

## Restoring

`Restore` refuses:
- a backup below the vault's counter, which would roll back security state;
- with `--counter-states`, a backup at the counter whose state isn't the one
  the vault counted (a fork's);
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
   itself. On a volume nothing was restored onto, `--restore` refuses to
   start, before it takes a generation, so a coordinator running on that
   volume keeps running.

With `--wrapping-key dev`, copy the dev key the backups were taken under to
`<dir>/wrapping.key` first. A new one would be made otherwise, and no backup
opens under it, so `--restore` refuses to start without the file.

### Rehearsing a restore: the drill

Rehearse with the drill, on any machine, before trying a restore anywhere
else:

```sh
scripts/restore-drill.sh        # add -v for the coordinators' logs
```

It needs no AWS account, vault or mail edge, and it runs two tests:

- `TestTheRestoreRunbookDrill` (`internal/coordinator/restoredrill_test.go`)
  runs a coordinator with mail on, over a fake mail edge. Backups go through
  the real S3 client (`internal/s3bucket`, signed requests, write-once `Put`,
  paged `List`) to an S3 stand-in over HTTP (`internal/s3bucket/s3buckettest`).
  The counter is the Cloud vault pair's wire protocol (`WireCounter` against
  `cloudvaulttest`). The test makes real state: a team, a worker with a
  mailbox, a file, and an email worked into a thread with a draft. It takes
  a backup, makes a security change, takes another, and checks the bucket
  holds no plaintext. Then it deletes the volume and, on a fresh one, runs
  the steps above in order:
  - the dry run moves nothing and writes nothing;
  - a restore of the backup from before the security change is refused, as
    a dry run and as a restore, and leaves the volume empty;
  - the newest is restored under a new generation. `state.json`, less the
    restore mark and the security sequence, and every file in every
    worker's tree are then the same, byte for byte, as before the loss.
    The restore counts itself: the volume and the vault go one past the
    backup's change, so from then on even the backup it was restored from,
    and any disk at the old count, is a rollback.

  The restored coordinator then works. Mail it had already worked isn't run
  again, the draft is approved and sent once under its Message-ID, and new
  mail runs. Its next security change is counted under the new generation,
  and the old generation's swap is refused.
- `TestTheRestoreRunbookOnTheBinary` (`cmd/fount-coordinator/drill_test.go`)
  runs the coordinator binary with this page's dev flags (`--wrapping-key
  dev --dev-vault … --backup-bucket … --restore …`) against the same S3
  stand-in. A worker's file and a finished job are backed up on the
  interval. A `--restore` over the live volume is refused without moving the
  dev vault. The volume is lost, keeping `wrapping.key` and the dev vault.
  `--restore` without the key refuses to start. The dry run names the newest
  backup, writes nothing and moves the vault nowhere. The restore serves the
  same files and job. A restart with `--restore` still set serves the
  restored volume.

What the drill can't cover, so the live checks below still need doing:

- **A real bucket.** The stand-in honours `If-None-Match` and pages `List`
  the way the client expects, but it is not S3. It doesn't cover S3's 409 for
  racing conditional writes, versioning, the lifecycle rule actually
  expiring old versions, or the forwarder and enclave egress.
- **IAM and the bucket policy.** The stand-in checks only that each request
  is signed by the expected access key. It doesn't check the signature, and
  it has no policy, so it can't show that a missing key is a 404 rather than
  a 403 under the IAM policy, that other principals are denied, or that the
  coordinator can't read old versions.
- **A deployed Cloud vault pair.** `cloudvaulttest` speaks the vault's wire
  protocol over one register. Replication between the two vaults, and the
  keyset pull that releases the wrapping key and bucket credentials to an
  attested release (`--wrapping-key vault`), are tested in fount-mail-vault
  and live, not here.
- **The real mail edge.** The package drill's edge is a fake. The binary drill
  runs without `--mail`, because a dev binary's `--mail` reaches the real
  edge. A send in flight across an edge reboot is in `TestTheRestoreDrill`
  (`restore_test.go`), also against the fake edge.
- **Dev keys outside the backup.** A dev build's (`-tags dev`) `job-signing.key`
  (`--runner-addr` without `--credentials`) lives in `--dir`, isn't backed
  up, and is made new on the restored volume. It is logged, and a dev proxy
  needs the new one.

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
  de-risk 2). `scripts/restore-drill.sh` rehearses it locally; the live run
  is what it can't cover (above).
- Against a deployed Cloud vault pair (`COORDINATOR_MODE`): a boot's
  certificate taken by the edge; a restore below the counter refused; an
  old-generation coordinator fenced at the counter and the edge; backups
  under the vault's S3 credentials; one vault down holding changes back
  (`ErrNotDurable`) without retiring the coordinator.
