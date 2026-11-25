# id.fount.sh, the team passkey's relying party

Team passkeys use the relying party `id.fount.sh`. This covers invite, passkey-join, passkey-vouch and recovery-start. The coordinator (`internal/coordinator/passkeyjoin.go` `PasskeyRPID`) and Desktop (`src-tauri/src/account/passkey_join.rs` `TEAM_PASSKEY_RP_ID`) accept assertions only for that RP ID and only from the origin `https://id.fount.sh`. Both sides check `testdata/team-passkey-join-vectors.json` (`rp_id`, `origin`), so they can't drift apart.

This file says what the host must serve. Hosting it is a later step: nothing here is deployed yet.

## Why a host of its own

Script running on an origin the RP ID covers can call `navigator.credentials.get({rpId: "id.fount.sh", challenge})` with any challenge. The member's synced passkey then answers with exactly the bytes the native app would produce. That is enough to mint every proof a team passkey makes, including adding a device to the member's team (security review 2026-11-24, H1). The RP used to be `fount.sh`, the marketing site, which serves a proxied Plausible script on every page.

So whoever controls this host controls the team passkeys. That includes the DNS for `fount.sh`, the hosting account and its deploy keys, and the TLS certificate. Treat that access like release signing.

The covered origins are `https://id.fount.sh` and any subdomain of it. WebAuthn lets an origin use an RP ID that equals its host or is a registrable suffix of it. `fount.sh` itself, and pages on it, can't use `id.fount.sh`.

## What it serves

| Path | Response |
|---|---|
| `/.well-known/apple-app-site-association` | 200, `Content-Type: application/json`, no redirect, body below |
| `/` | 200, the static page below |
| everything else | 404, empty body |

The AASA body covers only `webcredentials`. Invite links stay on `fount.sh/join`, under the `applinks` that `fount.sh`'s AASA lists.

```json
{"webcredentials":{"apps":["Q4W599RXFW.com.fount.app"]}}
```

The page at `/` is plain HTML with no script, no style, no images, no forms and no links off the host:

```html
<!doctype html><meta charset="utf-8"><title>Fount</title>
<p>This address holds Fount's passkey settings. There is nothing to do here.</p>
```

The host does not serve:
- **`/.well-known/webauthn` (related origins)**. It answers 404. Serving it would let the origins it lists use the RP ID in browsers. The verifiers refuse every other origin anyway, but nothing should be published that invites one.
- **`/.well-known/assetlinks.json`**. It answers 404 until an Android build exists. When one ships, add only `delegate_permission/common.get_login_creds` for that package and its signing certificate's SHA-256.

## Headers on every response

```
Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Permissions-Policy: publickey-credentials-get=(), publickey-credentials-create=()
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Frame-Options: DENY
Cache-Control: public, max-age=300
```

- **`Permissions-Policy`** turns WebAuthn off for documents on the host. Even an injected script then couldn't ask for an assertion without a header change too. Native apps never load the page, so they aren't affected.
- **No cookies**, and no `Set-Cookie`.
- **No analytics, rewrites or proxies** to third parties, and no serverless functions or middleware.

## Hosting and DNS

- **A project of its own**, not the fountlanding Vercel project or any project the marketing site deploys from. Deploy access is limited to release owners, and every change is reviewed. The content is the two files above, so it should rarely change.
- **DNS**: one record for `id.fount.sh`, with no wildcard `*.id.fount.sh` and no other names under it. `fount.sh` has CAA records naming the CA in use.
- **Caching**: Apple fetches the AASA through its CDN (`app-site-association.cdn-apple.com`), so a change takes hours to reach Macs. A signed build only uses passkeys once the CDN serves the file.

## Desktop

- **Entitlement**: `src-tauri/entitlements/app.plist` lists `webcredentials:id.fount.sh`. It also keeps `webcredentials:fount.sh`, which mailbox passkeys use.
- **Mailbox passkeys are not team passkeys**. The edge's `RECOVERY_RP_ID` (pause and recover a mailbox) is still `fount.sh`, so a mailbox passkey no longer signs anything for a team. Moving the edge's RP is separate work: it has the same exposure.
- **Windows**: `webauthn.dll` lets any local process ask for any RP ID, so local malware can still prompt for `id.fount.sh`. This doesn't change.

## Migration

A passkey made for `fount.sh` doesn't verify for `id.fount.sh`. This is acceptable before launch, but every existing team is affected:
- A listed `rec` made under `fount.sh` stops admitting new devices.
- A replayed log whose invite, passkey-join or vouch records carry `fount.sh` assertions is refused, by the coordinator and by Desktop. Dev teams made before the change have to be made again. This is expected; there are no production teams yet.
- After that, a member who has a listed computer sets up a new passkey from Members ("Set up your passkey"). A member who doesn't is invited again.

## Checking it before go-live

```
curl -sI https://id.fount.sh/.well-known/apple-app-site-association   # 200, application/json, the headers above
curl -s  https://id.fount.sh/.well-known/apple-app-site-association   # exactly the JSON above
curl -sI https://id.fount.sh/.well-known/webauthn                     # 404
curl -s  https://id.fount.sh/ | grep -ci '<script'                    # 0
swcutil dl -d id.fount.sh                                             # on a Mac: the CDN's copy
```
