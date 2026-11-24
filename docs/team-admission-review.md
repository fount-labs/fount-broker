# Team admission: what changed, for the security review

Step 5 of fount `docs/features/fount-fleet/team-billing-plan.md` (§6.1 D3, §6.2). Branch
`fleet/team-admission` in fount-broker, fount-infra and fount. It changes who the client channel
lets in, so it needs a review before it is merged or deployed.

## What admission was

- fount-infra issued a Cloud credential only to an account `evaluateCloudAccess` entitled (plus or
  pro, active or past_due, inside its period). Otherwise `403 no_access`.
- `channel.verifyHello` refused any credential whose own claims weren't entitled. The channel
  closed at the credential's `exp`, the session grant's `exp` or the paid period `pe`, whichever
  came first.
- Past the channel, every `/v1` route was checked against the team log only (`requireRole`,
  `requireMember`). Billing played no part: every caller had paid.

## What admission is now

1. **fount-infra** (`packages/shared/src/devices.ts` `buildCloudCredentialClaims`,
   `lambda/device` `issueCloudCredential`) gives every live device a Cloud credential. An entitled
   account's is unchanged. Any other account gets an *identity-only* one: `tier`, `status` and
   `pe` null, `exp = iat + 1h`, and `eml` as before (Clerk is now asked for every account).
2. **Channel** (`internal/channel/identity.go` `VerifyAccountCredential`, `channel.go`
   `verifyHello`):
   - A Cloud credential still has its signature, shape, `exp`, lifetime (at most 1 h) and `iat`
     (at most 5 min ahead) checked. Its entitlement is no longer checked there: the result is
     `Peer.Paid`.
   - A 7-day device credential must still be entitled itself, as before.
   - `cloudTiers` now includes `team`.
   - A paid peer's channel still closes at `pe`. An unpaid peer's closes at `min(exp, grant.exp)`.
   - `Peer.Paid` goes to `coordinator.Caller.Paid` (`cmd/fount-coordinator/client.go`).
3. **Coordinator** (`internal/coordinator/admission.go`). A caller with `Paid` is admitted exactly
   as before. For a caller without it:

   | Route | Unpaid caller |
   |---|---|
   | Any worker route (`requireRole`: reads, files, threads, ops, jobs, mail setup, export, `GET /v1/jobs/{id}`, `GET /v1/workers` listing) | Only on a worker of a **firm** team (`tm_…`) whose `Billing` is entitled, with the role the log gives. Solo-team worker: `ErrNoPlan`. Lapsed or unknown firm team: `ErrTeamUnpaid`. |
   | Ungranted worker (no team yet) | As `POST /v1/workers` below |
   | `POST /v1/workers` | Only if this device is admitted under an **admin** of a firm team that is entitled now |
   | `POST /v1/teams` (mint) | `ErrNoPlan` |
   | `POST …/invites/{id}/send` | Only while the firm team is entitled |
   | A list adding a new worker to a **solo** team | `ErrNoPlan` |
   | `GET /v1/teams`, `GET …/log`, invite open and accept, other lists, passkey-join, passkey-vouch, recovery-start, billing-statement, billing-refresh | Unchanged: membership and proof checks as before, no billing check |

   The admission check runs after the membership check, so a stranger still gets `ErrNoWorker` or
   `ErrNoTeam` (404), never a billing answer. Refusals are `402` with `code` set to `no_plan`,
   `team_unpaid` or `seats`.
4. **Seats** (`checkSeats`, called last in `checkList`), for firm teams with billing on and a list
   that doesn't delete the team. `count = len(list.Members)`: admins, reviewers and pending invites.
   The list is refused with `ErrSeats` when `count > seats && count > prior count`. `seats` is
   `max(Billing.Seats, 1)` while entitled, and `1` otherwise.
5. **Jobs** (`coordinator.go` `next`). A queued job of a firm team that isn't `teamPaid` doesn't
   start. `TeamRunners` counts neither its queued jobs nor its intake waits, so no runner is
   started for it.
6. **Lapse** (`lapse.go` `teamLapseDue`, from `renewDue` on each mail sweep):
   - Unpaid (fount-infra answered "not entitled"): each worker of the team takes `lapsed()` without
     asking its renewal, marked `Lapse.Team`.
   - Paid again: each `Lapse.Team` worker gets `resumed()`.
   - Unknown (no answer yet, or the last answer ran out while fount-infra fails): neither.
7. **Retired** (`TeamRunners`): a firm team whose `Billing` is `no_access` and either `canceled`,
   or not entitled for 30 days (`TeamBilling.Since`). A team that never had a subscription
   (`no_subscription`) is never retired for billing.
8. **Bug fixed on the way**: `commitEntry` rebuilt the `Team` on every append and dropped
   `Billing` (step 3). It now carries it over.

## Invariants to check

- **I1. No model call on an identity-only credential.** fount-infra's `verifyDeviceCredential`
  takes only `typ: fount-device`, so the proxy device lane and every device route refuse any
  `fount-cloud` credential as `malformed` before a lookup (`proxy-server/auth.test.ts`,
  `test/unit/device.test.ts`). Job credentials are separate and unchanged. A job's model calls
  are billed by `pay` (step 1), and an unpaid team's jobs don't start (I4).
- **I2. A credential alone opens nothing.** The hello still needs the device key's session grant
  and the TLS binding. The unpaid path adds no route that the team log doesn't already gate.
- **I3. Billing only narrows.** For a `Paid` caller every check is the old one. For an unpaid
  caller each route is the old check *and* a billing check. No route skips the membership or role
  check. (Exception by design: none. Invite acceptance needed only `eml` before, and still does.)
- **I4. An unpaid firm team runs nothing.** No job starts (`next`), and no runner start is asked
  (`TeamRunners`). Intake has no credentials and makes no model call; it runs only if a runner is
  already linked.
- **I5. Removals always pass.** A list that doesn't add a member passes the seat rule whatever
  `Billing` says. This covers role changes, worker removals, removing members and deleting the
  team.
- **I6. Fail closed on unknown billing.** A missing answer or a failing fount-infra admits no
  unpaid caller, starts no job and allows one seat. It doesn't lapse the edge or email admins,
  though.
- **I7. Admission is live.** Billing is read on each request, not at the handshake. A team that
  lapses mid-channel shuts its unpaid members out on their next request. A paid caller's channel
  still closes at `pe`.

## For the reviewer to weigh

- **Unpaid admins can make workers.** An unpaid admin of a paying team may `POST /v1/workers`.
  The plan's wording put "create a worker" under the caller's own plan; that would make a firm
  team's admins pay twice (a seat and a plan). The worker it makes is inert: it has no DEK or
  jobs, at most 4 per device and 16 per account, gone in 30 min. Only a list can take it in, and
  a solo team refuses it from an unpaid signer.
- **Minting still needs a plan.** The first admin of a firm team needs their own plan to mint it,
  as the plan says. A buyer with no plan can't start a team.
- **Unpaid members keep some routes.** Passkey-join, recovery and list signing still work for
  unpaid members of any team, solo teams included. None of them reads a worker or runs a job. It
  does let an unpaid former payer keep the team log moving.
- **Retirement can race a re-subscription.** A canceled team that subscribes again stays
  `retired` until the coordinator's next billing answer. That is daily, at the period end, or
  when Desktop calls `billing-refresh` after checkout. Step 7's `team-runners` backstop cancels
  a retired team's live subscription, so it must re-check the subscription itself before
  cancelling.
- **The device lane needs no plan here.** Step 6 still has to keep the proxy device lane
  refusing `fount-cloud`.

## Tests

- broker `internal/channel`: `TestACloudCredentialWithNoPlanIsDeferredToTheCoordinator`.
- broker `internal/coordinator/admission_test.go`:
  - `TestAListPastTheSeatsIsRefusedAndARemovalPasses`
  - `TestASoloTeamHasNoSeatsAndNeedsEachMembersPlan`
  - `TestAnUnpaidMemberOpensATeamWorkerButNotASoloRoute`
  - `TestABillingRefusalWithoutAnAnswerIsUnknown`
  - `TestAJobIsntStartedWhileTheTeamDoesntPay`
  - `TestAnEndedTeamIsRetired`
  - `TestBillingKeepsWhenItStoppedPayingAndAsksAgainAtTheEnd`
- broker `lapse_test.go`: `TestATeamLapsePausesAllItsWorkersAndResumes`.
- infra: `test/unit/device-credential.test.ts`, `test/unit/device.test.ts`,
  `proxy-server/auth.test.ts`.
