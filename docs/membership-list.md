# The membership list (grant v3)

Who may reach a Cloud worker, with which role, and how that changes. Short version: **each worker
has an append-only membership log in the coordinator. Its entries are lists signed by an admin
device and admission records for devices that joined under a list. Every request is checked
against the log's current state: the caller's device must be admitted under a listed member of
the caller's account, and the member's role must allow the operation.**

**Status, 2026-11-18.** Design, for review before any code. Nothing here is built.

Builds on `launch-plan.md` decisions 5, 17, 18, 24–27 and sections T and H,
`teams.md` §2, §7 and §11, and `cloud-worker-devices.md` (all in the fount repo,
`docs/features/fount-fleet/`). Claims about today's code were read in this repo at 027332b
(`internal/coordinator/grant.go`, `devicekey.go`, `api.go`, `threadops.go`, `state.go`,
`internal/channel/identity.go`).

---

## 0. Decisions at a glance

| # | Decision | § |
|---|---|---|
| 1 | One authority per worker: its **membership log**. Signed lists and admission records, one sequence, hash-chained. | 2 |
| 2 | A **list** names members (by account, or by email while invited), each member's role, and every device admitted so far. Only a device of a member who is admin in the previous list can sign the next one. | 2.2 |
| 3 | An **admission record** lets a device in without an admin online: an invite redeemed, a same-member device join, a passkey recovery. Each carries proof a client can check against the list. | 2.3 |
| 4 | Two roles: **admin** and **reviewer**. Every operation has a required role in one table, and an operation missing from the table is refused. | 3 |
| 5 | The caller is checked on **every request**, under the worker's lock, against the current log: account, device, role. Nothing is cached in the channel. | 3.2 |
| 6 | Each entry's `seq` is the head's plus one and its `prev` is the head's hash. A stale, replayed or forked entry is refused. Clients keep the highest `(seq, hash)` they've seen and refuse anything lower or different. | 4 |
| 7 | Every log append is security state (decision 17): durable in the backup and counted by the vault before it is acknowledged. A stale-generation coordinator can't append (decision 18). | 4.2 |
| 8 | The coordinator seals the DEK wraps itself. A list commits to the DEK, not to wraps. Address-key wraps go to admin devices only (decision 25). | 5 |
| 9 | v2 workers migrate lazily: their first v3 list is signed by any device v2 lists, makes the account's member an admin with every listed device, and continues the grant numbering. After it, v2 grants are refused. | 6 |
| 10 | Clerk and fount-infra only vouch for an account and a device. They never add a member, change a role or admit a device. | 7 |

---

## 1. What the code does today

- **The worker belongs to one account** (`Worker.Account`), and a request is allowed when the
  channel's account is the worker's and its device is in `Worker.Devices` (`api.workerByID`,
  `Worker.authorizes`, rechecked under the tree's lock in `loadTree` and `enqueueAs`).
- **Every listed device is equal.** A v2 grant from any listed device, numbered `GrantSeq + 1`,
  replaces the list. Any listed device can drop the others or revoke (delete) the worker
  (`grantee`).
- **A device is listed only on its own inclusion**, which binds its X25519 key to its Ed25519 key,
  the coordinator, the account, the worker, the DEK commitment and the grant that first listed it.
  `sinceFits` stops a removed device's old inclusion from re-adding it.
- **Desktop makes the wraps.** A grant carries each device's HPKE wrap of the DEK and signs their
  digest. The coordinator keeps them and never opens them, though it holds the DEK.
- **The channel's caller has no email or team** (`channel.DeviceClaims`: `acct`, `dev`, tier,
  status, paid period).

The membership list keeps the inclusion, the HPKE wrap format and the `aud` binding. It replaces
"every device is equal" with members and roles, and "every device change is a signed grant" with
signed lists plus admission records.

---

## 2. The membership log

### 2.1 Shape

Per worker, the coordinator keeps an ordered log `[e1, e2, …]`. Each entry is either a **list**
(§2.2) or a **record** (§2.3). Each has:

- `seq`: the head's `seq` + 1. One counter for both kinds. A migrated worker continues from its
  `GrantSeq` (§6).
- `prev`: `SHA-256(context ‖ payload)` of the head entry, base64url; empty only for `seq` 1 of a
  new worker.

The **state** of the log is what its head implies: the last list, plus every record after it.
Requests are checked against the state; history is kept so a client can verify the chain from the
last point it saw (§4.3).

The log is small (tens of entries a year), kept whole in `state.json` beside the worker, and never
compacted at launch.

### 2.2 The list

A list is an admin device's Ed25519 signature over `MembersContext` followed by the exact payload
bytes, sent as `base64url(payload) "." base64url(sig)`, as grants and inclusions are. The
coordinator stores the token as sent and hashes those bytes, so nothing is re-serialized and there
is no canonical-JSON step to get wrong.

```
MembersVersion = 3
MembersType    = "fount-worker-members"
MembersContext = "fount-worker-members-v3\n"

{
  "v": 3, "typ": "fount-worker-members",
  "aud": "<coordinator audience>",
  "worker": "w_…",
  "team": "<owning team id>",           // billing and ownership; a solo account is a team of one
  "dek": "<DEKCommitment>",
  "seq": 7, "prev": "<hash of entry 6>",
  "dev": "<signing device id>",
  "iat": 1795000000,
  "members": [                          // sorted by id, ids unique, 1..MaxMembers
    {
      "id": "m_…",                      // random, chosen by the admin device that first lists them
      "account": "acct_…",              // empty while only invited
      "email": "alice@firm.com",        // lower-cased; the invite's address
      "role": "admin" | "reviewer",
      "devices": [ {"id", "key", "enc", "since", "inclusion"} … ],   // sorted by id
      "invite": {"id", "commit", "exp"},  // optional: an open invite (§2.3)
      "rec": {"cred", "pub"}              // optional: the member's recovery passkey (§2.3)
    }
  ]
}
```

What the coordinator checks before it appends a list (every check is a refusal, never a repair):

1. **Form.** Strict decoding: no unknown fields, no duplicate keys anywhere (a Go decoder takes
   the last duplicate, serde the first, so a duplicate would let Desktop and the coordinator read
   two lists from one signature). `v`, `typ`, `aud` are this coordinator's; `worker` is the path's;
   `iat` within `MaxGrantAge` and `grantSkew`, as grants. Members sorted and unique by `id`;
   accounts unique; emails unique; devices unique across the whole list; at least one admin.
   Bounded: `MaxMembers` members, `MaxMemberDevices` devices each.
2. **Order.** `seq == head.seq + 1` and `prev == hash(head)`. Otherwise `ErrMembersStale`, which
   Desktop answers by fetching the log and signing again (an admission may have landed since it
   read).
3. **Signer.** `dev` is the channel's device, the payload is signed by the channel's device key,
   and in the **current state** (before this list) that device is admitted under a member whose
   role is admin and whose account is the channel's. A reviewer's device, a device of a removed
   member, or a device admitted under another member is `ErrNotAdmin`.
4. **DEK.** `dek` is the worker's `DEKCommitment`. A list can't change the DEK, as a grant can't.
5. **Devices.** Each device entry carries the inclusion that device signed (devicekey.go, version
   1, `seq` = the entry that first admitted it). The inclusion's key, X25519 key and account match
   the entry and the member, and `since` follows `sinceFits`: a device already admitted keeps its
   `since`, and a new one must be included for this list's `seq`. A device that the current state
   admits by a record is carried with that record's inclusion and `since`.
6. **Accounts.** A member's `account`, once bound by a record (an invite redeemed), can't change.
   An admin may set it directly only for a member the log hasn't bound yet (the founding admin,
   §6, or an admin's direct add of a known account).
7. **Itself.** The signer's own device stays admitted in the list unless another admin remains;
   a list that leaves no admin is refused.

Anything the list omits that the current state had is **removed** when it is appended: a member,
one of their devices, an open invite. Their wraps go at once and their next request fails (§3.2).
Because the list must be signed over the exact head, an admin can only remove what they saw.

### 2.3 Records

A record admits one device under one member without a new list. The coordinator writes it itself
after checking its proof, and the record keeps the proof, so a client can check it against the
list it follows. Shape, common to all kinds:

```
{ "kind", "seq", "prev", "member", "device": {"id","key","enc","since","inclusion"},
  "account", "at", "proof": {…} }
```

`since` is the record's own `seq`; the device signs its inclusion for it. Records are not signed by
the coordinator: a record's authority is its proof, and the coordinator's attestation is what
vouches for the checks a client can't repeat (the verified email, the wait).

The kinds, and who builds them. **Only the interfaces are part of this design; T and H build the
flows.**

| Kind | Proof | Checked by the coordinator | Built in |
|---|---|---|---|
| `invite` | the invite's secret, revealed once used | an open `invite` on the member in the state, `SHA-256("fount-worker-invite-v1\0" ‖ worker ‖ member ‖ secret) == commit`, before `exp`, not used before (a record for this invite id exists = used), the channel credential's **verified email** equals the member's email, the channel's account isn't another member's. Binds `account`. | T, invites (decision 26) |
| `join` | a signature by one of the member's admitted devices over `("fount-worker-join-v1", worker, join id, nonce, new key)` | the approver is admitted under the same member and the channel's account is the member's; the code comparison of `cloud-worker-devices.md` §2.3 happens on the devices | H, second device (decision 26, last paragraph) |
| `recovery-start` | a WebAuthn assertion by the member's `rec` passkey over `SHA-256(join id ‖ nonce ‖ new key)` | the passkey is the member's `rec` in the state; the channel's account is the member's. Starts a 72-hour wait; admits nothing. | H, recovery (decision 19) |
| `recovery-cancel` | a signature over `("fount-worker-recovery-cancel-v1", worker, start seq)` by any admitted device of the member or of an admin | the signer is admitted and the recovery is still waiting | H, recovery |
| `recovery-done` | the `recovery-start` record's `seq` | 72 hours have passed since it, and no `recovery-cancel` names it | H, recovery |

An admin re-adding a member's new device without the wait (decision 19) is just a list that pins
the device, so it needs no record kind.

Each record notifies the worker's admins (decision 26 step 5). The window to cancel is any admin's
next list, which removes the device by omitting it. The log is the used-token store for invite
secrets, so a restore can't make a secret usable again (§4.2).

### 2.4 Effective state, in one function

Every check below reads one derived view, recomputed when the log's head moves:

```go
type Role string // "admin" | "reviewer"

type Member struct {
	ID, Account, Email string
	Role               Role
	Devices            []Device // pinned by the list, plus admitted by records after it
}

// members is the worker's log reduced to who may act now.
type members struct {
	Seq     uint64
	Head    string // hash of the head entry
	ByID    map[string]*Member
	device  map[string]*Member // device id → member
}
```

`Worker.Devices` stays, derived from it, so the existing `authorizes`, `loadTree`, `enqueueAs` and
`workerByID` checks keep meaning "this device is admitted" without a rewrite.

---

## 3. Roles and the check on every operation

### 3.1 What each role may do

| Role | May |
|---|---|
| reviewer | Read the worker, its threads and files; start threads; send notes; cancel jobs; accept or discard proposals; approve, discard and resend drafts; answer, dismiss and forward questions; run held mail; claim; mark read |
| admin | All of that, plus: sign lists (add, remove, change roles, invite, pin devices), change the worker's settings and requesters, write the worker's own files, delete the worker, export it |

The table is one map in code, `opRoles`, keyed by route or operation kind:

| Operation | Role |
|---|---|
| `GET /workers`, `GET /workers/{id}`, files, threads, `GET /jobs/{id}`, `GET /workers/{id}/members` | reviewer |
| `startThread`, `sendNote`, `cancelJob`, `acceptProposal`, `discardProposal` | reviewer |
| `approveDraft`, `discardDraft`, `sendAgain`, `keepFileAsCopy`, `redoOnLatest` | reviewer |
| `answerQuestion`, `dismissQuestion`, `forwardQuestion`, `runHeldMail`, `markRead`, claims | reviewer |
| `POST /workers/{id}/members` (a list), `POST /workers/{id}/revoke` (delete) | admin |
| `addRequester`, `removeRequester`, `setRequesterMode`, `setDefaultMode`, `setAutoRun`, `pairingConfirm`, `setThreadReplyMode` | admin |
| `PUT /workers/{id}/root/{path}`, `POST /workers/{id}/jobs` (a raw JobSpec) | admin |
| export (H) | admin |

Records are posted by the device being admitted, which isn't a member yet; their routes are
authorized by their proof, not by a role.

### 3.2 Where the check runs

- **The channel** stays as it is: it proves an account and a device (and, for invites, a verified
  email, §7). It knows nothing of workers, so a list change needs nothing from it.
- **`api.workerByID`** becomes `api.access(id, need Role)`: the worker exists, the channel's device
  is admitted under a member whose `account` is the channel's, and that member's role is at least
  `need`. A worker the caller isn't on, or whose member is another account, is `ErrNoWorker`
  (404), as today, so it can't be told from a missing one. A member whose role is too low is
  `ErrRole` (403): they can see the worker, so hiding it would only confuse their app.
- **Under the lock.** The operation's own path rechecks the role where it rechecks the device
  today (`loadTree`, `enqueueAs`, the thread-op apply), with the role it was let in for. A list
  that removes a member or lowers a role takes the tree's lock first, as `Grant` does, so a request
  in flight finishes under the state it was allowed by and the next one sees the new state.
- **Default deny.** `opRoles` has an entry for every route and every operation kind the
  coordinator parses, including the ones that answer 501 today. A test walks `parseThreadOp`,
  `parseWorkerOp`, both `unsupported…Ops` maps and the mux's routes and fails on a kind with no
  role. A kind added without a role is refused at runtime too.
- **The coordinator's own operations** (mail arriving, a job ending, intake) act as `anyDevice`,
  as `mayAct` allows today, and need no role.

For the other lanes, the call is:

```go
// requireRole is the one check: the caller's device is admitted under a
// member of the caller's account, whose role is at least need. Called with
// c.mu held.
func (c *Coordinator) requireRole(caller Caller, workerID string, need Role) (*Member, error)

// opRole is the role an operation kind needs; ok is false for a kind with none.
func opRole(kind string) (Role, bool)
```

A new client-facing operation adds one line to `opRoles`. Operations the coordinator applies
itself don't.

---

## 4. Versions, rollback and generations

### 4.1 At the coordinator

- An entry is appended only as `head.seq + 1` with `prev == hash(head)`. A replayed list, a list
  signed against an older head, or a second list racing for the same `seq` is refused
  (`ErrMembersStale`); the first one wins, as decision 5 asks.
- A list is good for `MaxGrantAge` after `iat`, so a list signed and withheld can't be played
  much later even against an unchanged head.
- v2 grants are refused on a worker whose log has a v3 list (§6), so the old numbering can't be
  replayed into the new.

### 4.2 Across a restore (decision 17) and generations (decision 18)

Every append (a list, a record, a used invite) is **security state**. It is acknowledged only
after three steps, in order:

1. The new `state.json`, with the entry, is written to the volume.
2. The backup's root, which includes it, is written (H's backup loop, in the same synchronous path,
   not on its timer). Otherwise a crash before the next backup would lose an acknowledged removal,
   and the restore would bring the removed member back.
3. The vault's counter moves to the coordinator's new security sequence, with a compare-and-swap
   on `(generation, previous count)`.

A restore whose `state.json` has a security sequence below the vault's counter is refused.
Because step 3 is checked against the generation, a coordinator of an older generation (one a
restore or an upgrade replaced, still running on the other side of a partition) can't append: it
can't admit or remove anyone, and it can't consume an invite. H adds: such a coordinator stops
serving the channel once the vault refuses it, so it doesn't keep serving reads under a stale log.

The security sequence is coordinator-wide (one counter in the vault), not per worker. Each worker's
log `seq` is separate and is what clients see.

### 4.3 At the client

- Desktop keeps, per worker, the highest `(seq, hash)` it has verified.
- `GET /workers/{id}/members?since=N` returns the entries after `N`. Desktop verifies the chain
  from its point: each `prev`, each list's signature by an admin device of the state before it,
  each record's proof against that state. Then it moves its point.
- A head below its point, or the same `seq` with another hash, is a rollback or a fork. Desktop
  stops trusting the worker's state, shows it, and doesn't sign anything over it.

This is what makes a restore's rollback visible even if the vault check failed, and makes a
coordinator that forked the log visible to anyone who saw both branches.

---

## 5. Keys

- **DEK wraps.** v3 drops the grant's wraps and their digest. The coordinator holds the DEK, so it
  seals each admitted device's wrap itself (`SealWrap`) when the device is admitted, and drops it
  when the device goes. This is what lets an invite or a recovery admit a device with no other
  device online. The coordinator gains nothing: it already holds the DEK.
- **The first list of a new worker** is signed over the DEK commitment. A worker created in Cloud
  (lane A) gets its DEK from the coordinator, which tells the creating device the commitment to
  sign; a worker created over today's route sends the DEK with its first list, as the first grant
  does.
- **Address keys** (decision 25) are wrapped only to devices of admin members. A list that adds an
  admin wraps them to the new admin's devices; a list that removes an admin, or lowers an admin to
  reviewer, drops those wraps and marks the worker's address signing key for rotation at the edge
  (M). The mark is part of the same append.
- **Removal doesn't rotate the DEK** (`cloud-worker-devices.md` decision 6). A removed member's
  devices are refused at once; what they already read can't be taken back, and the dialog says so.

---

## 6. Migrating v2 workers

A v2 worker has one account and a flat device list, every device equal. Its migration:

1. Until its first v3 list, it runs as today. The state derived from a v2 worker has one member,
   the worker's account, role admin, with every listed device. That is exactly today's rule (every
   device may do everything), so the role check is in force from the first build without changing
   what anyone can do.
2. Any device v2 lists may sign the **genesis list**: `seq = GrantSeq + 1`, `prev` empty (allowed
   only while the worker has no log), one admin member with the worker's account and every listed
   device, carried with the inclusions they already have. This is the v2 rule authorizing its own
   replacement once.
3. From then on, `POST /grant` answers 409 for the worker, and `revoke` needs an admin device's
   signature on a v3 delete (`typ: "fount-worker-delete"`, same envelope as a list, naming the
   head it deletes at).
4. A new worker's first entry is a v3 list once Desktop ships v3. v2 grants are taken for workers
   with no v3 list for one coordinator release, then removed.

Desktop signs the genesis list without asking, the first time it opens a v2 worker after the
update. Nothing else changes for the user.

---

## 7. What fount-infra and Clerk do, and don't

- They vouch for **an account and a device** each time the channel opens, as today.
- For invites, the Cloud credential needs one more claim: the account's **verified email**
  (`eml`, present only when Clerk verified it). The coordinator compares it with the invite's. This
  is T's fount-infra work.
- For teams, the credential may carry the account's **team and team role**. The coordinator only
  shows them; Desktop may suggest "make Dev an admin" from a Clerk admin role, and an admin's device
  still signs it. **Clerk roles suggest, never grant** (decision 24).
- They can't add a member, change a role, admit a device or remove one: every one of those is an
  admin-signed list or a record with a proof they can't make (an invite secret they never saw, a
  listed device's approval, the member's passkey).

---

## 8. Threats, for the security review

The review in `launch-plan.md` T and `teams.md` §11 should take each of these.

| # | Threat | What stops it |
|---|---|---|
| 1 | fount-infra or Clerk mints a device on a member's account | It isn't admitted: a device needs a list, an invite secret, a listed device's approval or the passkey. It also fails the account check on another member's devices. |
| 2 | fount-infra or Clerk adds a person, or makes someone admin | Only an admin device's signature changes the list. Clerk's team role is never read as a grant. |
| 3 | A reviewer tries to act as admin: signs a list, deletes the worker, changes settings, removes a device | The signer must be an admin device in the state before the list; every op checks `opRoles`. |
| 4 | A list that escalates its own signer or names a new admin | Allowed only if the signer is already admin; an admin may make admins. Recorded in the log, visible to every client. |
| 5 | Replay of an old list, or a list signed over an old head | `seq`, `prev` and `iat` (§4.1). |
| 6 | Restore of an old snapshot re-admits a removed member or reopens a used invite | Appends are durable in the backup and counted by the vault before acknowledgement; older restores are refused; clients refuse a lower head (§4.2, §4.3). |
| 7 | A partitioned old-generation coordinator keeps admitting, removing or serving | It can't move the vault counter, so it can't append; H makes it stop serving. |
| 8 | A removed member keeps a session open | Authorization is per request, under the worker's lock, against the current state. The channel session doesn't carry membership. |
| 9 | A removed member keeps the DEK they opened | Accepted: no rotation on removal. The DEK opens only objects behind Fount's storage credentials. Address keys were never theirs unless admin; a removed admin rotates the signing key. |
| 10 | An invite link forwarded or intercepted | The secret is single-use, expires, and only admits an account whose verified email is the invite's. Anyone controlling that mailbox can accept it, as with every email invite; the admins are notified and can remove the device. |
| 11 | Parser differential between Desktop (serde) and the coordinator (Go) on the signed list | Strict decoding with unknown fields and duplicate keys refused on both sides; the stored token's bytes are what is hashed. A shared test vector set for both. |
| 12 | A list that leaves no admin, or whose signer drops itself with no other admin | Refused (§2.2 step 7). |
| 13 | The same device admitted under two members, or one account as two members | Refused: devices and accounts are unique across the list and the records. |
| 14 | A compromised coordinator enclave | Out of scope for the list: it holds the DEK. The chain still lets a client see a forged list (no admin signature) and a rollback; it doesn't stop a forged invite record, since the coordinator sees invite secrets. |
| 15 | Sizes: a list or log used to exhaust memory | `MaxMembers`, `MaxMemberDevices`, a body cap on `/members`, and one open invite per member. |

---

## 9. What changes in code (for stage 2)

New files, to stay clear of the other lanes:

- `internal/coordinator/members.go`: the types, `SignMembers` (the Rust reference, as `SignGrant`
  is), `parseMembers` with strict decoding, `members` reduction, `requireRole`, `opRoles`.
- `internal/coordinator/members_log.go`: appending, hashing, `ErrMembersStale`, migration from v2.
- `internal/coordinator/members_test.go`: the adversarial cases (wrong signer, reviewer signer,
  removed member's device, version rollback and replay, a fork at the same `seq`, role escalation
  by a reviewer, last admin removed, duplicate keys, unknown fields, an inclusion for the wrong
  `seq`), and the `opRoles` coverage test.

Small touches in shared files:

- `state.go`: `Worker.Log []MembersEntry` and `Worker.Team`.
- `api.go`: `workerByID` takes a role; `GET/POST /v1/workers/{id}/members`; `/grant` refuses a v3
  worker.
- `threadops.go`: one `opRole(kind)` call where the envelope's kind is parsed.
- `grant.go`: `Revoke` takes the v3 delete for a v3 worker.

The vault counter, backups and generation checks (§4.2) are H's; stage 2 leaves one hook,
`c.commitSecurity(func() error)`, which today saves `state.json` and later also writes the backup
root and moves the vault counter.

---

## Choices to confirm

1. **Records, not lists, for admissions.** Invites, same-member joins and recovery admit a device
   by a record the coordinator writes, so no admin has to be online. The alternative (every device
   pinned only by a list, a newly joined device usable only once an admin signs) is stricter but
   breaks decision 26's "the admin needn't be online".
2. **The coordinator seals DEK wraps** in v3, instead of Desktop. Needed for 1; it adds no trust,
   since the coordinator holds the DEK.
3. **Only admins remove devices**, including a reviewer's own lost laptop (decision 24 as
   written). Letting a member remove their own other devices would be harmless and saves the admin
   a step.
4. **Role assignments for settings-like operations.** `setThreadReplyMode`, `addRequester` and
   `pairingConfirm` are admin, since they change what leaves by email and to whom; `runHeldMail` is
   reviewer, since it decides one held message. `PUT /root/{path}` and raw `POST /jobs` are admin
   (decision 29 makes the worker's files read-only for members).
5. **A 403 for a member whose role is too low**, rather than the 404 a non-member gets.
6. **Membership is per worker, and team admins aren't automatic admins** of every team worker:
   Desktop adds them to each list it signs. An automatic rule would make a Clerk role grant.
7. **Migration may be unnecessary.** The production coordinator starts on the production wrapping
   key (G), which can't open a dev volume, so no v2 worker reaches production. §6 is cheap, but
   the alternative is to refuse v2 outright and wipe the dev coordinator.
8. **Synchronous backup of every security append** (§4.2 step 2). It makes membership changes as
   slow as one S3 write. The alternative, a vault counter that lags the backup, can't tell a fresh
   restore from a rollback.
9. **Bounds:** `MaxMembers` 50 and `MaxMemberDevices` 8 per worker, against today's `MaxDevices`
   16 for the whole worker.
