# Compatibility contract

Reference implementation: `zccz14/auth-mini` at `27f8aaf`.
Vendored verbatim: `openapi.yaml` (36 paths), `sql/schema.sql` → `migrations/0001_init.sql`
(dropping `PRAGMA foreign_keys`, which D1 always enforces).

Nothing in this repo may change a wire-level detail below without a matching change in the
reference repo and an entry in "Divergences".

## L1 — access tokens

Header, claim order and value rules copied from `rust-backend/src/jwks.rs::sign_access_token`:

```
header : {"alg":"EdDSA","kid":"<kid>","typ":"JWT"}
payload: {"sub","sid","iss","aud","amr","auth_admin","typ":"access","iat","exp"}
```

| Field | Rule |
|---|---|
| `sub` | user UUID |
| `sid` | session id (UUID v4, lowercase) |
| `iss` | `app_meta.issuer` |
| `aud` | **one** audience serializes as a bare string, several as an array (`audience_json`) |
| `amr` | `[auth_method]`, or `[auth_method, source_auth_method]` when delegated (e.g. SSO) |
| `auth_admin` | whether the user is `app_meta.admin_user_id` |
| `exp` | `iat + 900` |
| signature | Ed25519 over the ASCII bytes of `header.payload`, base64url **without padding** |

`/jwks` returns `{"keys":[public_jwk, ...]}` ordered CURRENT then STANDBY, public material
only. `kid` is opaque; migrated keys keep their legacy `kid` values verbatim.

## L1 — token material and timestamps

| Material | Legacy rule | Here |
|---|---|---|
| refresh token | `lower(hex(randomblob(32)))` → 64 lowercase hex chars | `randomHex(32)` |
| `sessions.refresh_token_hash` | lowercase hex of SHA-256 over the token | `sha256Hex` |
| session id | UUID v4, lowercase | `uuidv4` |
| `expires_at` | RFC 3339, millisecond precision, `Z` suffix | `nowRfc3339Millis` |
| refresh lifetime | 2 592 000 s | `REFRESH_TOKEN_SECONDS` |

Migrated `sessions` rows stay refreshable only if all five match, so these are covered by
unit tests rather than trusted.

## Email delivery (phase 2)

Cloudflare blocks outbound TCP to port 25, so "same SMTP as now" cannot mean a port-25 relay.
What it does mean, and what this repo implements:

- the `smtp_configs` table and its weighted pick are kept as-is (same columns, same ordering,
  same `is_active` filter, same bucket arithmetic);
- the TLS mode follows the legacy rule in `build_smtp_transport`, which is *not* "secure means
  implicit TLS": `secure && port == 465` is implicit TLS, `secure && port != 465` is STARTTLS,
  and `false` is explicit cleartext. Port 587 with `secure = 1` therefore means STARTTLS;
- submission happens over `cloudflare:sockets` to **587 with STARTTLS** or **465 with implicit
  TLS** — port 25 is the only blocked port, submission ports are allowed;
- the client refuses to send credentials to a server that does not offer STARTTLS rather than
  silently downgrading;
- 10 s timeout, and a rejected `RCPT TO` fails the send instead of reporting success.

### Verified against production (2026-10-26)

The live `smtp_configs` row is `smtp.feishu.cn:587`, username `auth@ntnl.io`, sender
`NTNL Authenticator <auth@ntnl.io>`, `secure = 1`. No password was ever copied off the production
host — every check below either ran on that host or used a deliberately wrong password.

| Check | Where it ran | Result |
|---|---|---|
| STARTTLS submission with real credentials, real message | production host | **delivered**, no refused recipients |
| implicit TLS on 465 with real credentials | production host | AUTH accepted |
| implicit TLS on **587** | production host | fails, `WRONG_VERSION_NUMBER` — 587 is STARTTLS-only |
| connect → EHLO → STARTTLS → EHLO → AUTH from Cloudflare egress | Worker on `*.workers.dev`, colo SIN | reached `AUTH`, server answered `535` (wrong password by design) |

The third row is what makes the fourth meaningful: Feishu's 587 must be spoken to with STARTTLS,
so a client that treats `secure = 1` as implicit TLS would fail in production. That bug existed in
this repo and was found by this test, not by review — `transportModeFor` now encodes the legacy
rule and is covered by a test.

Remaining unverified: a successful authenticated send *from Cloudflare* (needs the real password at
the edge, which is a deliberate step for whoever loads the config into D1/Secrets, not a test).

## WebAuthn (phase 6)

Five paths: `POST /webauthn/register/options`, `POST /webauthn/register/verify`,
`POST /webauthn/authenticate/options`, `POST /webauthn/authenticate/verify`,
`DELETE /webauthn/credentials/{id}`.

The ceremony checks — CBOR, COSE keys, attestation statements, DER signatures, origin and rpIdHash
comparisons — come from **`@simplewebauthn/server` 14**, which verifies on WebCrypto and runs
unchanged on workerd. That is also the lineage: auth-mini's passkeys were produced by this library
before the backend moved to `webauthn-rs`, so the port returns to the implementation real devices
were first tested against. No code here parses webauthn-rs's serde layout.

What stays hand-written is everything the contract pins down:

| Piece | Rule |
|---|---|
| `challenge` | 32 random bytes, base64url, 43 characters |
| `user.id` | `sha256("auth-mini-webauthn-user-handle\0" + user_id)` cut to 16 bytes, version-5 UUID bits, base64url |
| `pubKeyCredParams` | `[{alg:-7,type:"public-key"},{alg:-257,type:"public-key"}]` — webauthn-rs's `secure_algs()` |
| `authenticatorSelection` | `{requireResidentKey:true, residentKey:"required", userVerification:"required"}` |
| `extensions` | `{credProps:true}` |
| `timeout` | `300000` |
| dropped from registration | `attestation`, `hints`, `excludeCredentials` — the legacy projection sends none of them |
| authentication options | `{challenge, rpId, timeout, userVerification:"required"}`, no `allowCredentials` |

`serde_json` renders maps with sorted keys, so the responses here are emitted in the same
alphabetical order (`publicKey` before `request_id`; `authenticatorSelection, challenge, extensions,
pubKeyCredParams, rp, timeout, user`). A test pins the key order rather than leaving it to chance.

Verification matches the legacy `UserVerificationPolicy::Required` (`requireUserVerification: true`,
`requireUserPresence: true`) and accepts only those two algorithms, so a credential the legacy server
would have refused cannot slip in here.

### Stored credential

`webauthn_credentials.passkey_json` keeps its column name but holds a neutral document:

```json
{"format":"auth-mini-passkey","version":1,"id":"<b64url credential id>",
 "public_key":"<b64url COSE key>","counter":0,"transports":["internal","hybrid"],
 "user_handle":"<b64url 16-byte handle>","rp_id":"auth.ntnl.io"}
```

`format`/`version` are the guard: a legacy row that has not been through the exporter fails
`parsePasskey` and answers `400 invalid_webauthn_authentication`, instead of being misread as a
credential of ours.

`tools/webauthn-export` produces that document. It links `webauthn-rs` 0.5.5 — the crate and version
the legacy server runs — so each row is read by the code that wrote it, and rebuilds the COSE key in
wire form because that is what `@simplewebauthn/server` decodes on every sign-in. The credential does
not store the user handle (webauthn-rs keeps it only in the in-flight registration state), so the
exporter derives it from the user id with the legacy `user_webauthn_id` function; `cargo test` there
pins the same vector as `tests/webauthn.test.ts`, and the two implementations agree byte for byte.

Dry run against the production database (2026-10-26, read-only): **20 credentials for 13 users, 20
exported, 0 failures**, all ES256, all `transports: null`. Every exported public key was then parsed
by `@simplewebauthn/server`'s `decodeCredentialPublicKey` and decoded as EC2 / P-256 / ES256. What
that cannot prove — that a signature verifies, and that a device's stored handle matches the derived
one — is the cutover checklist's "one real device passkey sign-in", and a mismatch fails closed.

### Who may manage passkeys

Legacy `authorize_passkey_registration`: an `email_otp` or `webauthn` session may register and delete
freely; an `ed25519` session may register **only the caller's first passkey**, which is how a device
key bootstraps a passkey without being able to extend its own trust. The rule is checked before the
ceremony and again by a conditional `INSERT ... WHERE NOT EXISTS (SELECT 1 ... WHERE user_id = ?)`,
so a second ceremony cannot land in the gap between check and write. Deleting a credential requires a
strong session — an Ed25519 session gets `403 insufficient_authentication_method`.

### Config resolution

`issuer` becomes the ceremony origin, and `rp_id` must equal the origin host or be a parent domain of
it; IP hosts and `localhost` are accepted only as the exact host. The stored issuer has **no**
trailing slash (production holds `https://auth.ntnl.io`), and a slash makes origin normalisation fail
closed — the same rule `PUT /admin/config` applies on the way in.

### Verified against production (2026-10-26)

| Check | Result |
|---|---|
| `app_meta` read over SSM | `issuer = https://auth.ntnl.io`, `rp_id = auth.ntnl.io`, `brand_name = No Trade No Life` |
| `POST https://auth.ntnl.io/webauthn/authenticate/options` | `{"publicKey":{"challenge":"<43 chars>","rpId":"auth.ntnl.io","timeout":300000,"userVerification":"required"},"request_id":"<uuid>"}` |
| key order in that response | `publicKey` then `request_id`; CORS `*` |

That production call created one throwaway challenge row on the legacy server, which expires in five
minutes; nothing else was touched.

## L1 — Ed25519 device auth (phase 3)

`/ed25519/start` returns a `challenge` string; the device signs the **raw UTF-8 bytes of that
string** and posts a base64url signature. Any change in encoding invalidates every
provisioned device key, so it is specified here before implementation.

## L2 — HTTP surface

36 paths, see `openapi.yaml`. `tests/contract.test.ts` asserts every implemented route exists
in the spec; the unimplemented remainder is the roadmap in the README.

## GUI

The browser console is a wholesale copy of the legacy `ui-web` — all 16 routes, not a
reimplementation — served by this Worker under `/web/` through the Static Assets binding.
`web/src/sdk/` is the legacy SDK vendored in so the pages and the published
`auth-mini-react-components` keep their `auth-mini/sdk/*` imports; `openapi.yaml` here is
byte-identical to the legacy spec the generated client came from, so the two cannot drift silently.

Three screens call endpoints this Worker does not implement, so they fail at runtime while the rest
of the console works:

| Screen | Endpoint | State |
|---|---|---|
| `/email` | `POST /me/email/start`, `/me/email/verify` | among the 11 unimplemented paths |
| `/admin/resources` | `GET /admin/resources` | never implemented (deliberate deviation) |
| `/admin/request-audit` | `GET /admin/request-audit` | never implemented (deliberate deviation) |

`/sessions` lists sessions, but revoking one peer session (`POST /session/{id}/logout`) is also
missing. Until those land, the three screens render their error state rather than wrong data.

## Migration inventory (phase 8)

| Table | What moves | Transform |
|---|---|---|
| `users` | id, email, `email_verified_at`, `created_at` | copy as-is — `id` must survive, downstream apps key on it |
| `app_meta` | issuer, rp_id, brand_*, admin_user_id | copy as-is |
| `jwks_keys` | **private** material for CURRENT and STANDBY | copy as-is — without this every issued token dies at cutover |
| `sessions` | live rows with `expires_at > now` | copy as-is, or accept a forced re-login (decide at cutover) |
| `webauthn_credentials` | `passkey_json` | `tools/webauthn-export` reads each row with `webauthn-rs` 0.5.5 and emits the neutral document above; see the WebAuthn section for the 20-row production dry run |
| `ed25519_credentials` | public keys | copy as-is |
| `user_directory_token` | token hash | copy as-is — Linkit reads the user-id directory through it |
| `email_otps`, `*_challenges`, `remote_login_requests` | transient | do not migrate; they expire in minutes |

## Divergences and open questions

These are deliberate, or need confirming against the legacy test suite before cutover:

1. **Unknown route** → currently `404 {"error":"not_found"}`. The legacy body/code has not been
   confirmed; adjust here once the ported suite says otherwise.
2. **Signing key storage** → still `jwks_keys` in D1 in v1, because the cutover imports legacy
   private keys. Moving the private half into a Worker Secret is the planned v1.1 step; it must
   not change `/jwks`.
3. **`/admin/database`** → cannot exist as a file export on D1. Replaced by
   `wrangler d1 export` / Time Travel plus an encrypted off-platform snapshot.
4. **`/admin/resources`** → `sysinfo` host metrics are meaningless on Workers; replaced by
   platform observability.
5. **Rate limiting** → the legacy `/email/start` has none. A Durable Object token bucket is
   added here as a security fix, not as parity; it must fail closed without changing the
   documented success/error codes for normal traffic.
6. **Duplicate JSON keys** → `serde` rejects them for structs; `JSON.parse` keeps the last one.
   `src/http/strict-json.ts` restores the strict behaviour, and unknown-field rejection mirrors
   `#[serde(deny_unknown_fields)]` on every request struct.
7. **`id` must equal `rawId`** on both ceremonies. The legacy parser only checked that each was
   non-empty; both decode to the same bytes in every real client, so a mismatch is a malformed
   request and is rejected up front.
8. **`authenticatorAttachment` is accepted** on `/webauthn/authenticate/verify`, because
   `openapi.yaml` allows it there — the Rust struct would have rejected it. The value is ignored;
   it is client-asserted and carries no trust.
9. **`userHandle` is compared** with the stored handle when the authenticator sends one. The legacy
   path identified the user by which credential matched and never looked at the handle; a
   discoverable credential always returns it, so this only rejects a credential presented under
   someone else's handle.
10. **First-passkey race** → the batch spends the challenge and then refuses the insert, where the
    legacy transaction rolled back both. Reachable only when two ceremonies for one user run
    concurrently; it fails closed and costs that user one retry.

## Runtime budget: no paid plan assumed

Everything here is designed to fit Workers Free plus D1 Free:

| Limit (Free) | Consequence for this design |
|---|---|
| 10 ms CPU per request | no CPU-heavy work on the request path; WebCrypto and D1 do the heavy lifting, SMTP wait time is I/O, not CPU |
| 100 000 requests/day | far above a brand-owned auth server's sign-in volume |
| 50 subrequests per request | one SMTP connection plus a handful of D1 queries per sign-in |
| D1: 5 GB, 100 k rows written/day | the auth database is a few thousand rows |

`send_email` (Cloudflare Email Service) is **not** used: sending to arbitrary recipients needs the
Workers Paid plan, and it would replace the SMTP accounts rather than keep them.

## Sign-in flow as implemented

`POST /email/start` → code stored as a hash with a 10-minute expiry, then delivered. If delivery
fails the code is invalidated in the same request, so a user can never face a code they could not
have received.

`POST /email/verify` → audiences are resolved *before* the code is consumed (a bad `redirect_uri`
must not burn the user's code), then a single conditional `UPDATE ... WHERE code_hash = ? AND
consumed_at IS NULL AND expires_at > now` decides success. Two concurrent verifications of the
same code cannot both win: D1 reports the changed-row count, and the loser gets
`invalid_email_otp`.

Smoke-tested against the real D1 and the real SMTP account on 2026-10-26 (throwaway deployment,
deleted afterwards):

| Call | Result |
|---|---|
| `GET /jwks` | two keys bootstrapped into D1 and returned |
| `POST /email/start` with `nope` | `400 invalid_request` |
| `POST /email/start` with a real address | `200 {"ok":true}` in 3.5 s, message delivered |
| `POST /email/verify` with a wrong code | `401 invalid_email_otp` |
| `POST /email/verify` with an extra field | `400 invalid_request` |

Known gap, blocking public exposure: `/email/start` is unauthenticated and unlimited, so it would
be an open mail-sending endpoint. Rate limiting lands before cutover.

## Session lifecycle

| Route | Rule |
|---|---|
| `POST /session/refresh` | row must exist and be live; a mismatched refresh token answers `401 session_superseded`, and so does losing the conditional `UPDATE` race. The refresh token rotates and the 30-day window restarts on every successful refresh. |
| `POST /session/logout` | expires the caller's own session by moving `expires_at` to now — the same trick the legacy server used, so an already-issued access token dies on the next call that touches the session row. |
| `GET /me` | requires a live session **and** the self audience: a token delegated to a downstream app cannot read the profile. Returns the legacy shape, including `webauthn_credentials`, `ed25519_credentials` (read straight from their tables, so migrated rows show up before those flows are implemented) and `active_sessions`. |
| `GET /time` | `{now, now_ms, iso}` with `cache-control: no-store`. |

Access-token authentication is stricter than signature checking: after verifying the JWT by
`kid`, the session row must still exist, still be unexpired, still belong to the same user, and
still carry the same audience set as the token. Audiences are therefore part of the session
identity, not just a claim.

Smoke-tested against the real D1 on 2026-10-26 (throwaway deployment, deleted afterwards):
`GET /time` correct, `GET /me` without a token `401 invalid_access_token`,
`POST /session/refresh` with an unknown session `401 session_invalidated`,
`POST /session/logout` without a token `401 invalid_access_token`.

## Ed25519 device auth

| Route | Rule |
|---|---|
| `POST /ed25519/start` | Body is the device's **public key** (base58, 32 bytes), not a credential id. It must match exactly one registered credential; the response is `{request_id, challenge}` with a 300 s challenge of 64 hex characters. Unknown keys answer `400 invalid_ed25519_authentication`. |
| `POST /ed25519/verify` | Audiences resolve first, then the challenge must be unconsumed and unexpired, the signature is checked, and only then is the challenge spent by one conditional `UPDATE`. Replay answers `400 invalid_ed25519_authentication`. |
| `/ed25519/credentials` (GET/POST), `/ed25519/credentials/{id}` (PATCH/DELETE) | Require a session established with `email_otp` or `webauthn` — an `ed25519` or delegated session gets `403 insufficient_authentication_method`. Duplicate public keys answer `400 invalid_ed25519_credential`; unknown ids answer `404 credential_not_found`. |

Two byte-level details everything depends on: the signed message is the **raw UTF-8 bytes of the
challenge string**, and the signature is **base64url without padding**. Both are pinned by tests
that sign with a real Ed25519 key.

Live round trip against the real D1 (throwaway deployment, rows removed afterwards): start
returned a challenge, a locally signed challenge returned `200` with a token whose `amr` is
`["ed25519"]`, replaying the same request answered `400`, and a wrong signature answered `400`.

## Remote approval login

`POST /remote-login/start` takes no credentials: it resolves audiences like every other flow and
returns `{request_id, exchange_code, confirmation_code, expires_at}` — a 64-hex code the device
keeps, and an 8-character uppercase code the human reads out. Both are stored only as hashes.

`claim` binds the request to the approving user by the short code (`pending` and
`approved_user_id IS NULL` are both conditions of the `UPDATE`, so two people cannot claim the
same request). `pending` first marks stale rows `expired`, then lists what this user still has to
decide. `approve`/`deny` are conditional on `approved_user_id = caller`, so one user cannot decide
another's request. `exchange` is unauthenticated by design — the device has no session yet — and
spends the request with one conditional `UPDATE` before minting an `agent_approval` session, so a
replayed exchange answers `401 remote_login_unavailable` instead of minting twice.

`POST /session/authorize` delegates: it mints an `sso` session whose `amr` carries the source method
(`["sso","email_otp"]`), and refuses to put the issuer audience on a non-loopback target, so a
remote site cannot obtain main-site tokens by delegating through it.

Live run against the real D1 (throwaway deployment, rows deleted afterwards): device sign-in
produced a token, `start` issued codes, `pending` was empty, `claim` returned the summary,
`pending` then listed it, `approve` answered `{ok:true}`, `exchange` returned a token pair, and the
replay answered `401`.

## Identity directory

Three paths serve the integration that enumerates accounts: `GET /admin/users`,
`GET|POST|DELETE /admin/user-directory-token` and `GET /integration/user-ids`.

The directory token is `am_uid_` plus 32 random bytes as hex — 71 characters — stored only as the
lowercase hex of its SHA-256, the same shape the legacy `user_directory_token` row already carries,
so the existing token can be copied at cutover instead of every consumer being reissued. `POST`
returns the plaintext exactly once, on rotation; `GET` reports only `{configured, created_at}`;
`DELETE` drops the row. Every request compares the presented token against the stored hash, so a
rotation kills the previous token on the next call — there is no cache to wait out.

`/integration/user-ids` is server-to-server: the directory token buys `{"user_ids": [...]}` and the
response deliberately carries **no CORS headers**, so a browser page cannot read the user list even
if it somehow holds the token. `tests/directory.test.ts` asserts that absence, because folding this
route into the shared header map would silently undo the decision.

`/admin/users` reports per-user credential and session counts. The active-session count compares
`expires_at` against an RFC 3339 timestamp derived from the request clock rather than against
`CURRENT_TIMESTAMP`: `expires_at` carries a `T` where SQLite renders a space, so the legacy
string comparison was decided by the separator instead of the date and counted nonsense.

Live run against the real D1 (throwaway deployment, rows deleted afterwards): `POST` returned
`am_uid_` + 64 hex — 71 characters — exactly once; `/integration/user-ids` answered
`{"user_ids":["<seeded user>"]}` with no `access-control-allow-origin` anywhere in the response and
answered `401` to a well-formed but unknown token; `/admin/users` reported `active_session_count: 1`
for that user; a rotation made the previous token answer `401` on its very next call while the new one
answered `200`; and `DELETE` returned `204`, after which the status was `{"configured":false}` and the
last good token answered `401`.

## Key rotation

`POST /admin/jwks/rotate` promotes STANDBY into CURRENT and mints a fresh STANDBY, in **one D1
batch** — a half-applied rotation would leave an instance that can neither verify its recently
issued tokens nor sign new ones.

The promoted key is one downstream caches already hold, which is the point of keeping a spare
published. The old CURRENT leaves `/jwks`, so tokens it signed stop verifying; the blast radius is
the 900 s access-token lifetime, not a revocation list.

Verified against the real D1 with a throwaway Worker that called the same function: `before`
CURRENT `bM4n…`/STANDBY `ShBt…`, after rotation CURRENT `ShBt…`/STANDBY `j79c…`, and `/jwks`
served the promoted pair with the old CURRENT gone.

## Admin bootstrap

`PUT /admin/setup` installs the first admin Ed25519 key and the user row that owns it; a second
call answers `409 already_initialized`, and `GET /admin/setup` answers `403` once an admin exists.

**Divergence:** the legacy server gated setup on the caller being on loopback. A Worker has no
loopback, so the gate here is "no admin exists yet" plus an optional `ADMIN_SETUP_TOKEN` header
check. Set that variable in production: without it, the window between deploy and the owner
claiming admin is open to anyone who reaches the URL.

`PUT /admin/config` requires an admin token and enforces the legacy rules: issuer must be
`scheme://host[:port]/` with no credentials, query, fragment or path; `rp_id` must be a plain DNS
name and must equal or be a parent domain of the issuer host (never an IP, never `localhost`
unless the issuer is localhost); the SMTP array replaces the table wholesale, an existing id with
an empty password keeps the stored secret, and a new row without a password is rejected. The
response never contains a password — the wire shape is `AdminSmtpConfigSummary`, snake_case.

A bug this caught: the strict JSON decoder treated every string as a potential key, so a body
that reused one string as two different values (`username` and `from_email` both `auth@ntnl.io`)
was rejected as `duplicate_field`. It now tracks object context and only counts strings in key
position, with a regression test.

## Cutover shape

Freeze writes on the legacy server → export SQLite → import into D1 with the transforms above →
start this Worker with the **legacy JWKS keys** → run the ported integration suite plus a real
device passkey sign-in → reconcile counts (users, credentials, sessions) → flip the route →
leave the legacy server read-only for seven days with a single declared write authority.
No dual writes, ever.
