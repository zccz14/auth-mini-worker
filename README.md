# auth-mini-worker

Auth Mini, reimplemented as a Cloudflare-native Worker.

The goal is **contract compatibility, not code parity**: [auth-mini](https://github.com/zccz14/auth-mini)
stays the reference implementation and the test oracle until traffic has moved and the
rollback window has closed.

## What "compatible" means here

| Layer | Contract | Why it matters |
|---|---|---|
| L1 | JWT + JWKS (`alg: EdDSA`, `kid`, `iss`, `aud`, `amr`, `auth_admin`, `typ: access`) | every downstream backend verifies tokens against `/jwks`; a drift logs everyone out |
| L2 | the 36 HTTP paths in [`openapi.yaml`](./openapi.yaml) | the browser/device SDK and `auth-mini-react-components` speak these directly |
| L3 | login redirect, remote approval, silent SSO delegation | the preferred sign-in flow is "approve remotely, get a code" |

`openapi.yaml` is vendored verbatim from `zccz14/auth-mini` at commit `27f8aaf` and is the
source of truth for L2. [`docs/COMPATIBILITY.md`](./docs/COMPATIBILITY.md) records the exact
claim layout, token material rules and the migration inventory.

## Status

Phase 2 — storage and mail transport. Implemented:

- `GET /jwks`, Ed25519 sign/verify, access-token claims, strict request decoding, CORS.
- D1 `auth-mini` created (APAC, `86c6dcd6-4c00-413e-b695-aec3b4cb9b98`) with the legacy schema
  applied; `wrangler.jsonc` points at it.
- SMTP submission over `cloudflare:sockets` (587 STARTTLS / 465 implicit TLS) with the legacy
  weighted `smtp_configs` selection, plus audience resolution ported from the legacy server.

- **Email OTP sign-in works end to end**: `POST /email/start` and `POST /email/verify`, against the
  real D1 database and the real SMTP account, verified by a throwaway deployment that was deleted
  right after the test.

- **Session lifecycle**: `/session/refresh` (rotating refresh token, superseded detection),
  `/session/logout`, `/me`, `/time`.

- **Admin bootstrap and config**: `GET|PUT /admin/setup` (first run only), `GET|PUT /admin/config`
  (issuer, RP id, branding, SMTP rows).

- **Ed25519 device auth**: `/ed25519/start`, `/ed25519/verify` (signature over the raw challenge
  bytes), plus credential list/create/rename/delete behind a strong session.

- **Key rotation**: `GET /admin/jwks`, `POST /admin/jwks/rotate` (STANDBY promoted to CURRENT in
  one D1 batch).

- **Remote approval login**: `/remote-login/start|pending|claim|{id}/approve|{id}/deny|{id}/exchange`
  and `/session/authorize` for SSO delegation.

Not implemented yet: `/session/{id}/logout` (peer logout, needs passkey-management auth), the
remaining `/admin/*`, `/webauthn/*`,
the login GUI, and the data migration. Nothing is deployed and no route is publicly reachable.

**Do not expose this publicly yet**: `/email/start` has no rate limiting, so a public URL would be
an open mail-sending endpoint. A Durable Object token bucket has to land before any cutover.

## Local development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm dev                      # wrangler dev, local D1
pnpm db:migrate:local         # apply migrations/ to the local D1
```

## Roadmap

1. ~~**Foundation**: schema, crypto, `GET /jwks`, contract harness.~~ Done.
2. ~~**Email OTP sign-in**: `/email/start`, `/email/verify`.~~ Done.
3. ~~**Session lifecycle**: `/session/refresh`, `/session/logout`, `/me`, `/time`.~~ Done.
4. ~~**Admin bootstrap + config**~~ Done. The instance can be pointed at
   `https://auth.ntnl.io` instead of the `localhost` seed.
5. ~~**Ed25519 device auth** (`/ed25519/*`).~~ Done, including a live signature round trip.
6. ~~**Key rotation**~~ Done.
7. ~~**Remote approval login** (`/remote-login/*`, `/session/authorize`).~~ Done.
8. ~~**Identity directory**: `/admin/users`, `/admin/user-directory-token`,
   `/integration/user-ids`.~~ Done, including a live rotation that kills the old token.
9. ~~**Passkeys**: `/webauthn/*` on WebCrypto, plus the one-shot exporter that converts legacy
   `passkey_json` rows.~~ Done: routes verified against a software authenticator, and
   `tools/webauthn-export` already rewrites the 20 production credentials cleanly.
10. **Login GUI** as Static Assets, at parity with the embedded `ui-web` build.
11. **Rate limiting** for `/email/*` and `/remote-login/start` before anything is publicly
    reachable.
12. **Migration + cutover**: import users, credentials, live JWKS keys and sessions from a
    frozen SQLite snapshot; then flip traffic with the old server read-only for rollback.

## Licence

MIT, same as the original.
