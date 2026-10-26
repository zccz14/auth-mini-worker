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

Not implemented yet: the `/email/*`, `/session/*` and `/webauthn/*` routes, the login GUI, and
the data migration. Nothing is deployed and no route is publicly reachable.

## Local development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm dev                      # wrangler dev, local D1
pnpm db:migrate:local         # apply migrations/ to the local D1
```

## Roadmap

1. **Foundation** (this PR): schema, crypto, `GET /jwks`, contract harness.
2. **Email OTP + sessions** (next): `/email/start`, `/email/verify`, `/session/refresh`,
   `/session/logout`, `/me`, `/time`.
3. **Ed25519 device auth**: `/ed25519/*` — challenge bytes must match the legacy server exactly.
4. **Admin**: `/admin/setup`, `/admin/config`, `/admin/users`, `/admin/jwks(+rotate)`, `/admin/user-directory-token`, `/integration/user-ids`.
5. **Passkeys**: `/webauthn/*` on WebCrypto, plus the one-shot exporter that converts legacy
   `passkey_json` rows.
6. **Remote login / SSO**: `/remote-login/*`, `/session/authorize`.
7. **Login GUI** as Static Assets, at parity with the embedded `ui-web` build.
8. **Migration + cutover**: import users, credentials, live JWKS keys and sessions from a
   frozen SQLite snapshot; then flip traffic with the old server read-only for rollback.

## Licence

MIT, same as the original.
