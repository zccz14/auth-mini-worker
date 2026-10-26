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
- submission happens over `cloudflare:sockets` to **587 with STARTTLS** or **465 with implicit
  TLS** — port 25 is the only blocked port, submission ports are allowed;
- the client refuses to send credentials to a server that does not offer STARTTLS rather than
  silently downgrading;
- 10 s timeout, and a rejected `RCPT TO` fails the send instead of reporting success.

Two things still need a real-world check before cutover, because they cannot be settled by unit
tests: whether the configured account accepts submission from Cloudflare egress, and whether
465 works with `secureTransport` as expected — if it does not, point the row at 587. Neither
needs a paid plan.

## WebAuthn (phase 5, deliberately deferred)

Not implemented in this repo yet. Two facts shape the eventual port:

1. Auth Mini's passkeys were originally produced by **`@simplewebauthn/server`**; the format only
   changed when the backend moved to Rust (`webauthn-rs`). That means the target format is a
   documented, widely used one rather than something invented here.
2. The TS→Rust conversion therefore exists in `zccz14/auth-mini` git history (see commits around
   "remove Node backend runtime"), so the `passkey_json` exporter can invert a change that was
   actually made instead of guessing at a serde layout.

Until then, no `/webauthn/*` route is registered and the contract test still passes because the
routes simply do not exist yet.

## L1 — Ed25519 device auth (phase 3)

`/ed25519/start` returns a `challenge` string; the device signs the **raw UTF-8 bytes of that
string** and posts a base64url signature. Any change in encoding invalidates every
provisioned device key, so it is specified here before implementation.

## L2 — HTTP surface

36 paths, see `openapi.yaml`. `tests/contract.test.ts` asserts every implemented route exists
in the spec; the unimplemented remainder is the roadmap in the README.

## Migration inventory (phase 8)

| Table | What moves | Transform |
|---|---|---|
| `users` | id, email, `email_verified_at`, `created_at` | copy as-is — `id` must survive, downstream apps key on it |
| `app_meta` | issuer, rp_id, brand_*, admin_user_id | copy as-is |
| `jwks_keys` | **private** material for CURRENT and STANDBY | copy as-is — without this every issued token dies at cutover |
| `sessions` | live rows with `expires_at > now` | copy as-is, or accept a forced re-login (decide at cutover) |
| `webauthn_credentials` | `passkey_json` | one-shot exporter runs `webauthn-rs` natively and emits neutral JSON (cred_id, COSE key, counter, user_handle, transports); never hand-parse its serde shape |
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

## Cutover shape

Freeze writes on the legacy server → export SQLite → import into D1 with the transforms above →
start this Worker with the **legacy JWKS keys** → run the ported integration suite plus a real
device passkey sign-in → reconcile counts (users, credentials, sessions) → flip the route →
leave the legacy server read-only for seven days with a single declared write authority.
No dual writes, ever.
