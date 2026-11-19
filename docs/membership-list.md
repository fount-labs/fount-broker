# The team membership log (grant v3)

Who may reach a Cloud worker, with which role, and how that changes. Short version: **each team
has one append-only membership log in the coordinator. Its entries are lists signed by an admin
device and admission records for devices that joined under a list. Each worker belongs to one
team. A team's admins are admins of every one of its workers; a reviewer reaches the workers the
list assigns them. Every request is checked against the log's current state: the caller's device
must be admitted under a listed member of the caller's account, and the member's role must allow
the operation on that worker.**

**Status, 2026-11-18.** Design reviewed by the user the same day (team-scoped authority, no v2
migration). Built in `internal/coordinator/members*.go`.

Builds on `launch-plan.md` decisions 5, 17, 18, 24–27 and sections T and H,
`teams.md` §2, §7 and §11, and `cloud-worker-devices.md` (all in the fount repo,
`docs/features/fount-fleet/`). Claims about the code before this change were read at 027332b.

---

## 0. Decisions at a glance

| # | Decision | § |
|---|---|---|
| 1 | One authority per **team**: its membership log. Signed lists and admission records, one sequence, hash-chained. | 2 |
| 2 | A **list** names the team's members (by account, or by email while invited), each one's role, the devices admitted so far, the team's workers, and which workers each reviewer reaches. Only a device of a member who is admin in the state before it can sign the next one. | 2.2 |
| 3 | Each worker belongs to one team and **inherits its admins**. A solo account is a team of one, whose id is the account's. | 2.2 |
| 4 | An **admission record** lets a device in without an admin online: an invite redeemed, a same-member device join, a passkey recovery. Each carries proof a client can check against the list. | 2.3 |
| 5 | Two roles: **admin** and **reviewer**. Every operation has a required role in one table; an operation missing from it is refused. | 3 |
| 6 | The caller is checked on **every request** against the current state: account, device, role and, for a reviewer, the worker. Nothing is cached in the channel. | 3.2 |
| 7 | Each entry's `seq` is the head's plus one and its `prev` is the head's hash. A stale, replayed or forked entry is refused. Clients keep the highest `(seq, hash)` they've seen and refuse anything lower or different. | 4 |
| 8 | Every append is security state (decision 17): durable and counted before it is acknowledged. A stale-generation coordinator can't append (decision 18). | 4.2 |
| 9 | The coordinator seals the DEK wraps itself. Address-key wraps go to every admin device for every team worker (decision 25). Losing an admin rotates the address signing key of every team worker. | 5 |
| 10 | No migration. v2 grants are refused outright; the dev coordinator is wiped. | 6 |
| 11 | Clerk and fount-infra only vouch for an account and a device. They never add a member, make an admin, change a role or admit a device. | 7 |

---

## 1. What the code did before

- **A worker belonged to one account** (`Worker.Account`), and a request was allowed when the
  channel's account was the worker's and its device was in `Worker.Devices`.
- **Every listed device was equal.** A v2 grant from any listed device, numbered `GrantSeq + 1`,
  replaced the list; any listed device could drop the others or revoke (delete) the worker.
- **A device was listed only on its own inclusion**, binding its X25519 key to its Ed25519 key, the
  coordinator, the account, the worker and the DEK.
- **Desktop made the wraps** and the grant signed their digest. The coordinator kept them and never
  opened them, though it held the DEK.

The team log keeps the self-signed inclusion (now team-scoped), the HPKE wrap format and the `aud`
binding. It replaces "every device is equal, per worker" with members and roles per team, and
"every device change is a signed grant" with signed lists plus admission records.

---

## 2. The team log

### 2.1 Shape

Per team, the coordinator keeps an ordered log `[e1, e2, …]`. Each entry is either a **list**
(§2.2) or a **record** (§2.3). Each has:

- `seq`: the head's `seq` + 1. One counter for both kinds, starting at 1.
- `prev`: the head entry's hash, base64url; empty only for `seq` 1.

An entry's hash is `SHA-256(context ‖ payload)`: for a list, `TeamListContext` and the payload
bytes as signed; for a record, `TeamRecordContext` and the record's JSON as stored.

The **state** is what the head implies: the last list, plus every record after it. Requests are
checked against the state; history is kept so a client can verify the chain from the last point
it saw (§4.3). The log is small, kept whole in `state.json` under `teams`, and never compacted at
launch.

### 2.2 The list

A list is an admin device's Ed25519 signature over `TeamListContext` followed by the exact payload
bytes, sent as `base64url(payload) "." base64url(sig)`, as grants were. The coordinator stores the
token as sent and hashes those bytes, so nothing is re-serialized and there is no canonical-JSON
step to get wrong.

```
TeamListVersion = 3
TeamListType    = "fount-team-members"
TeamListContext = "fount-team-members-v3\n"

{
  "v": 3, "typ": "fount-team-members",
  "aud": "<coordinator audience>",
  "team": "<team id>",                  // a solo account's team id is its account id
  "seq": 7, "prev": "<hash of entry 6>",
  "dev": "<signing device id>",
  "iat": 1795000000,
  "members": [                          // sorted by id, ids unique, 1..MaxMembers, ≥ 1 admin
    {
      "id": "m_…",                      // chosen by the admin device that first lists them
      "account": "acct_…",              // empty only while invited
      "email": "alice@firm.com",        // lower-cased; required while invited
      "role": "admin" | "reviewer",
      "workers": ["*"] | ["w_…", …],    // reviewers only: all the team's workers, or these
      "devices": ["<team inclusion>", …],   // sorted by device id, 0..MaxMemberDevices
      "invite": {"id", "commit", "exp"},    // optional: one open invite (§2.3)
      "rec": {"cred", "pub"}                // optional: the member's recovery passkey (§2.3)
    }
  ],
  "workers": [ {"id": "w_…", "dek": "<DEKCommitment>"}, … ]   // sorted by id, 0..MaxTeamWorkers
}
```

A **team inclusion** is what a device signs to be listed in a team: `TeamInclusionContext =
"fount-team-device-v1\n"`, claims `{v: 1, typ: "fount-team-device", aud, team, acct, dev, key,
enc, seq}`, where `key` and `enc` are its Ed25519 and X25519 public keys and `seq` the log entry
that first admits it. It no longer names a worker or a DEK: a device is admitted to a team, and
the list says which workers it reaches.

What the coordinator checks before it appends a list. Every check is a refusal, never a repair.

1. **Form.** Strict decoding: no unknown fields and no duplicate keys anywhere. A Go decoder takes
   the last duplicate and serde the first, so a duplicate would let Desktop and the coordinator
   read two lists from one signature. `v`, `typ` and `aud` are this coordinator's; `team` is the
   path's; `iat` is within `MaxGrantAge` and `grantSkew`. Members sorted and unique by `id`;
   accounts, emails and devices unique across the list; at least one admin; an admin has no
   `workers`, a reviewer has `["*"]` or sorted, unique ids of the list's workers; a member with no
   account has an email and an invite, and no devices. Bounded: `MaxMembers`,
   `MaxMemberDevices`, `MaxTeamWorkers`.
2. **Order.** `seq == head.seq + 1` and `prev == hash(head)`; otherwise `ErrTeamStale`, which
   Desktop answers by fetching the log and signing again (an admission may have landed since it
   read).
3. **Signer.** `dev` is the channel's device and the channel's device key signed the payload.
   In the **state before this list**, that device is admitted under an admin member whose account
   is the channel's. A reviewer's device, a removed member's, or another member's is
   `ErrNotAdmin`. For the first list (`seq` 1) there is no state: the team must be the channel's
   own account (a team of one), and the signer must be listed in it under an admin member of that
   account.
4. **Devices.** Each inclusion is signed by the key it names, for this coordinator and team, with
   the member's account. A device the state already admits keeps its inclusion's `seq` and keys,
   under the same member; any other must be included for this list's `seq`. So a removed device's
   old inclusion can't bring it back.
5. **Accounts.** A member's account, once the state has one, can't change.
6. **Workers.** A worker the state lists keeps its DEK commitment. A worker new to the team must be
   one the coordinator made over the channel and hasn't given a team yet, made by a device this
   list admits under an admin, and come with its DEK, which matches the commitment.

Anything the list omits that the state had is **removed** when the list is appended: a member,
one of their devices, an open invite, a reviewer's worker, a worker. A removed device's wraps go
at once and its next request fails (§3.2); a removed worker is deleted, as a revoke did (refused
while it runs a job). Because the list must be signed over the exact head, an admin can only
remove what they saw.

### 2.3 Records

A record admits one device under one member without a new list. The coordinator writes it after
checking its proof, and the record keeps the proof, so a client can check it against the list
before it. Shape, common to all kinds:

```
TeamRecordContext = "fount-team-record-v1\n"

{ "kind", "seq", "prev", "member", "account", "device": "<team inclusion>"?, "at", "proof": {…} }
```

The device's inclusion is for the record's own `seq`. Records aren't signed by the coordinator: a
record's authority is its proof, and the coordinator's attestation vouches for the checks a
client can't repeat (the verified email, the wait).

The kinds, and who builds them. **Only the interface is built here; T and H build the flows and
their proof checks**, and call `appendRecord` (§9) once a proof checks out.

| Kind | Proof | Checked by the coordinator | Admits | Built in |
|---|---|---|---|---|
| `invite` | the invite's secret, revealed once used | an open invite on the member, `SHA-256("fount-team-invite-v1\0" ‖ team ‖ member ‖ secret) == commit`, before `exp`, not used before (a record for it exists = used), the channel credential's **verified email** is the member's, and the channel's account isn't another member's. Binds `account`. | a device | T, invites |
| `join` | a signature by one of the member's admitted devices over `("fount-team-join-v1", team, join id, nonce, new key)` | the approver is admitted under the same member; the channel's account is the member's. The code comparison of `cloud-worker-devices.md` §2.3 happens on the devices. | a device | H, second device |
| `recovery-start` | a WebAuthn assertion by the member's `rec` passkey over `SHA-256(join id ‖ nonce ‖ new key)` | the passkey is the member's `rec`; the channel's account is the member's. Starts a 72-hour wait. | nothing | H, recovery |
| `recovery-cancel` | a signature over `("fount-team-recovery-cancel-v1", team, start seq)` | the signer is admitted under the member or under an admin, and the recovery still waits | nothing | H, recovery |
| `recovery-done` | the `recovery-start` record's `seq` | 72 hours have passed and no `recovery-cancel` names it | a device | H, recovery |

An admin re-adding a member's new device without the wait (decision 19) is a list that lists the
device, so it needs no record kind.

Each admission notifies the team's admins (decision 26 step 5). The window to cancel is any
admin's next list, which removes the device by omitting it. The log is the used-token store for
invite secrets, so a restore can't make a secret usable again (§4.2).

### 2.4 The state, as code reads it

```go
type Role string // RoleAdmin | RoleReviewer

type Member struct {
	ID, Account, Email string
	Role               Role
	Workers            []string     // a reviewer's; "*" is all the team's
	Devices            []TeamDevice // listed, plus admitted by records after the list
}
```

A worker's `Devices` stays, derived from its team's state whenever the head moves: every admin's
devices and the devices of reviewers assigned to it, each with a DEK wrap the coordinator sealed.
So the existing under-the-lock checks (`loadTree`, `enqueueAs`) keep meaning "this device may reach
this worker" without a rewrite, and a removal takes effect in them at once.

---

## 3. Roles and the check on every operation

### 3.1 What each role may do

| Role | May |
|---|---|
| reviewer | On the workers assigned to them: read the worker, its threads and files; start threads; send notes; cancel jobs; accept or discard proposals; approve, discard and resend drafts; answer, dismiss and forward questions; run held mail; claim; mark read. Read the team's log. |
| admin | On every worker of the team: all of that, plus change the worker's settings and requesters, write its own files and queue raw jobs. On the team: sign lists (members, roles, assignments, invites, devices, workers; deleting a worker is omitting it), export (H). |

The table is one map in code, `opRoles`, keyed by route pattern or operation kind:

| Operation | Role |
|---|---|
| `GET /workers`, `GET /workers/{id}`, files, threads, `GET /jobs/{id}`, `GET /teams/{team}/log` | reviewer |
| `POST /workers/{id}/threads/{tid}/ops`, `POST /workers/{id}/ops` (each kind is checked again below) | reviewer |
| `startThread`, `sendNote`, `cancelJob`, `acceptProposal`, `discardProposal` | reviewer |
| `approveDraft`, `discardDraft`, `sendAgain`, `keepFileAsCopy`, `redoOnLatest` | reviewer |
| `answerQuestion`, `dismissQuestion`, `forwardQuestion`, `runHeldMail`, `markRead` | reviewer |
| `POST /teams/{team}/log` (a list) | admin, checked by the list's signer rule |
| `addRequester`, `removeRequester`, `setRequesterMode`, `setDefaultMode`, `setAutoRun`, `pairingConfirm`, `setThreadReplyMode` | admin |
| `PUT /workers/{id}/root/{path}`, `POST /workers/{id}/jobs` (a raw JobSpec) | admin |

`POST /workers` (a new worker, before a list adds it to the team) needs no role: it makes a
placeholder only its device sees. Records are posted by the device being admitted, which isn't a
member yet; their routes are authorized by their proof.

### 3.2 Where the check runs

- **The channel** stays as it is: it proves an account and a device (and, for invites, a verified
  email, §7). It knows nothing of teams.
- **Every `/v1` route** finds its role in `opRoles` from its pattern, before it touches the worker.
  A worker the caller can't reach (another team's, one the caller's reviewer role isn't assigned
  to, one whose member is another account) is `ErrNoWorker` (404), as before, so it can't be told
  from a missing one. A member who reaches the worker with too low a role is `ErrRole` (403).
- **Thread and worker operations** check their kind's role too, after the envelope is parsed.
- **Under the lock.** A list takes the tree locks of every worker of the team before it changes
  the state, as a grant did, so a request in flight finishes under the state it was allowed by.
  The tree paths recheck the device against the worker's derived `Devices`, so a removed member or
  device fails there even if its route check passed first.
- **Default deny.** A route or kind with no entry in `opRoles` is refused. A test walks every
  route of `AccountHandler`, every kind `parseThreadOp` and `parseWorkerOp` know and both
  `unsupported…Ops` maps, and fails on any without a role.
- **The coordinator's own operations** (mail arriving, a job ending, intake) act as `anyDevice`,
  as `mayAct` allows, and need no role.

For the other lanes:

```go
// requireRole is the one check: the caller's device is admitted under a
// member of the caller's account in the worker's team, who reaches the worker
// with at least need. Called with c.mu held.
func (c *Coordinator) requireRole(caller Caller, workerID string, need Role) (*Member, error)

// opRole is the role an operation kind or route needs; ok is false for one
// with none, which is refused.
func opRole(kind string) (Role, bool)
```

A new client-facing operation adds one line to `opRoles`. Operations the coordinator applies
itself don't.

---

## 4. Versions, rollback and generations

### 4.1 At the coordinator

- An entry is appended only as `head.seq + 1` with `prev == hash(head)`. A replayed list, a list
  signed over an older head, or a second list racing for the same `seq` is `ErrTeamStale`; the
  first one wins, as decision 5 asks.
- A list is good for `MaxGrantAge` after `iat`, so a list signed and withheld can't be played much
  later even against an unchanged head.

### 4.2 Across a restore (decision 17) and generations (decision 18)

Every append (a list, a record, a used invite) goes through `commitSecurity`, which acknowledges it
only after three steps, in order:

1. The new `state.json`, with the entry and the coordinator's next security sequence, is written.
2. The backup's root, which includes it, is written (H's backup loop, in the same synchronous path,
   not on its timer). Otherwise a crash before the next backup would lose an acknowledged removal,
   and the restore would bring the removed member back.
3. The vault's counter moves to the new security sequence, with a compare-and-swap on
   `(generation, previous count)`.

A restore whose security sequence is below the vault's counter is refused. Because step 3 is
checked against the generation, a coordinator of an older generation (one a restore or an upgrade
replaced, still running across a partition) can't append: it can't admit or remove anyone, make an
admin, or use an invite. H adds that such a coordinator stops serving the channel once the vault
refuses it, so it doesn't keep serving reads under a stale log.

The security sequence is coordinator-wide (one counter in the vault). Each team's `seq` is
separate and is what clients see. Today `commitSecurity` does step 1 only.

### 4.3 At the client

- Desktop keeps, per team, the highest `(seq, hash)` it has verified.
- `GET /teams/{team}/log?since=N` returns the entries after `N` and the head. Desktop verifies the
  chain from its point: each `prev`, each list's signature by an admin device of the state before
  it, each record's proof against that state. Then it moves its point.
- A head below its point, or the same `seq` with another hash, is a rollback or a fork. Desktop
  stops trusting the team's state, says so, and signs nothing over it.

---

## 5. Keys

- **DEK wraps.** The coordinator holds each worker's DEK, so it seals each reaching device's wrap
  itself (`SealWrap`, under the team id as the account) whenever the state changes, and drops it
  when the device no longer reaches the worker. This lets an invite or a recovery admit a device
  with nobody online. The coordinator gains nothing: it holds the DEK already.
- **A new worker** comes with its DEK in the list that adds it to the team, as the first grant did.
  A worker created in Cloud (lane A) may get its DEK from the coordinator instead, which tells the
  admin device the commitment to sign.
- **Address keys** (decision 25) are wrapped to every admin device for every team worker: a new
  worker's to all the current admin devices, and a new admin's devices get every team worker's.
  Address keys aren't in the coordinator yet (lane A); the state gives lane A the admin devices.
- **Losing an admin** — removing an admin member, demoting one to reviewer, or removing one of an
  admin's devices — marks the address signing key of **every** team worker for rotation at the
  edge (lane M), in the same append (`Team.Rotate`). A removed device held those keys' wraps
  whichever of the three it was.
- **Removal doesn't rotate the DEK** (`cloud-worker-devices.md` decision 6). A removed member's
  devices are refused at once; what they already read can't be taken back, and the dialog says so.

---

## 6. No migration

No v2 worker reaches production: the production coordinator starts on the production wrapping key
(G), which can't open a dev volume. So there is no v2 → v3 path. `POST /v1/workers/{id}/grant` and
`/revoke` answer 410, the v2 grant and inclusion code is gone, and the dev coordinator's volume is
wiped when this ships. Desktop moves to the team log in the same release.

---

## 7. What fount-infra and Clerk do, and don't

- They vouch for **an account and a device** each time the channel opens, as before.
- For invites, the Cloud credential needs one more claim: the account's **verified email**
  (`eml`, present only when Clerk verified it). The coordinator compares it with the invite's. This
  is T's fount-infra work.
- They never make an admin. A Clerk organisation role, if the credential carries one, may be shown
  or used by Desktop to suggest a change; an admin's device still signs it.
- They can't add a member, change a role, admit a device or remove one: every one of those is an
  admin-signed list, or a record with a proof they can't make (an invite secret they never saw, a
  listed device's approval, the member's passkey).

---

## 8. Threats, for the security review

The review in `launch-plan.md` T and `teams.md` §11 should take each of these.

| # | Threat | What stops it |
|---|---|---|
| 1 | fount-infra or Clerk mints a device on a member's account | It isn't admitted: a device needs a list, an invite secret, a listed device's approval or the passkey. |
| 2 | fount-infra or Clerk adds a person, or makes someone admin | Only an admin device's signature changes the list. No credential claim is read as a role. |
| 3 | A reviewer acts as admin: signs a list, changes settings, writes the worker's files, deletes a worker | The signer must be an admin device in the state before the list; every route and kind checks `opRoles`. |
| 4 | A reviewer reaches a worker they aren't assigned | `requireRole` checks the assignment; the worker's derived `Devices` don't include them. 404. |
| 5 | An admin escalates someone | Allowed: admins may make admins. It is in the log, signed, and every client sees it. |
| 6 | Replay of an old list, or a list signed over an old head | `seq`, `prev` and `iat` (§4.1). |
| 7 | A restore of an old snapshot re-admits a removed member, un-demotes an admin or reopens a used invite | Appends are durable and counted by the vault before acknowledgement; older restores are refused; clients refuse a lower head (§4.2, §4.3). |
| 8 | A partitioned old-generation coordinator keeps admitting, removing or serving | It can't move the vault counter, so it can't append; H makes it stop serving. |
| 9 | A removed member keeps a session open | Authorization is per request against the current state, and rechecked under the tree's lock. |
| 10 | A demoted admin's admin-only write (a file, a raw job) in flight when the list lands | Its route check passed before the list; the tree path rechecks the device, not the role, so the write can finish. Narrow: they were admin a moment before. A removed member's can't. |
| 11 | A removed member keeps the DEK they opened | Accepted: no DEK rotation on removal. Address keys rotate when an admin is lost (§5). |
| 12 | An invite link forwarded or intercepted | Single use, expiring, and only for an account whose verified email is the invite's. Whoever controls that mailbox can accept it, as with every email invite; admins are notified and can remove the device. |
| 13 | Parser differential between Desktop (serde) and the coordinator (Go) on a signed list | Strict decoding with unknown fields and duplicate keys refused on both sides; the stored bytes are what is hashed; shared test vectors (`testdata/team-vectors.json`). |
| 14 | A list that leaves no admin | Refused. |
| 15 | One device under two members, one account as two members, or a worker in two teams | Refused. |
| 16 | Someone claims a team id first | The first list of a team must be for the signer's own account id. Firm teams' ids are open (below). |
| 17 | A compromised coordinator enclave | Out of scope: it holds the DEKs. The chain still lets a client see a list no admin signed and a rollback; it doesn't stop a forged invite record, since the coordinator sees invite secrets. |
| 18 | A list or log used to exhaust memory | `MaxMembers`, `MaxMemberDevices`, `MaxTeamWorkers`, a body cap on the route, one open invite per member. |

---

## 9. In code

- `internal/coordinator/members.go`: roles, `opRoles`, `requireRole`, the team's state.
- `internal/coordinator/teamlist.go`: the list and team inclusion formats, `SignTeamList` and
  `SignTeamInclusion` (the references for Desktop's Rust, as `SignGrant` was), strict parsing.
- `internal/coordinator/teamlog.go`: appending lists and records, the checks in §2.2, deriving each
  worker's devices and wraps, `commitSecurity`, the routes.
- `state.go`: `State.Teams`, `State.SecuritySeq`, `Worker.Team`. `api.go`: the role on every route.
  `threadops.go`: the kind's role. `grant.go` and `devicekey.go`: the v2 grant and inclusion go;
  the wrap stays.

For T and H: `appendRecord(caller, team, rec, check)` appends a record once its proof checks out,
under the same order and durability rules as a list.

---

## Choices to confirm

1. **Losing an admin's device rotates too.** Rotation is on removing or demoting an admin, and also
   on removing one of an admin's devices, since that device held the address keys' wraps. A lost
   laptop then costs one rotation of every team worker's signing key.
2. **A firm team's id.** The first list of a team must be for the signer's own account, so a solo
   team's id is its account id and nobody can claim another's. A Clerk organisation's team needs a
   rule: either a random id the coordinator makes at the first list (fount-infra maps it to the
   organisation for billing), or the organisation id with the credential naming the account's
   organisation (membership only, never a role). The first can't be squatted; the second is
   simpler for billing. Not built until T's accounts work.
3. **Reviewer assignments** are `["*"]` (every team worker, including later ones) or an explicit
   list. A worker added later reaches an explicit-list reviewer only when an admin adds it.
