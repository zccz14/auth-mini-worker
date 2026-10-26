# webauthn-export

Rewrites legacy `webauthn_credentials.passkey_json` rows into the neutral document the Worker
stores, so migrated passkeys keep working and nobody has to register again.

The legacy column holds `webauthn-rs`'s own serde shape. Nothing in the Worker parses that shape, and
neither does this tool by hand: it links **`webauthn-rs` 0.5.5 — the crate and version the legacy
server runs** — and reads the row with the code that wrote it. What it rebuilds is the COSE public
key in wire form (a CBOR map with integer keys), because that is what `@simplewebauthn/server`
decodes on every sign-in.

## Usage

```sh
cargo build --release

sqlite3 -readonly /var/lib/auth-mini/auth-mini.sqlite \
  "SELECT json_object('credential_id', credential_id, 'user_id', user_id,
                      'rp_id', rp_id, 'passkey_json', passkey_json)
   FROM webauthn_credentials;" \
| ./target/release/webauthn-export > neutral.jsonl          # inspection

… | ./target/release/webauthn-export --sql > update.sql      # what D1 will execute
```

`--sql` emits one `UPDATE webauthn_credentials SET passkey_json = … WHERE credential_id = …;` per row;
apply it with `wrangler d1 execute auth-mini --remote --file update.sql`.

The tool exits non-zero if any row fails, and prints the reason per row on stderr. A row is refused
when `passkey_json` does not deserialize, when its credential id disagrees with the column, or when
the key algorithm is not ES256/RS256 — the same two algorithms the Worker accepts.

## What the neutral document carries

```json
{"format":"auth-mini-passkey","version":1,"id":"…","public_key":"…","counter":0,
 "transports":["internal"],"user_handle":"…","rp_id":"auth.ntnl.io"}
```

`user_handle` is derived from the user id with the legacy `user_webauthn_id` function
(SHA-256 over `"auth-mini-webauthn-user-handle\0" + user_id`, first 16 bytes, version-5 UUID bits).
The credential itself does not store the handle, but a discoverable sign-in hands it back, so both
sides must agree byte for byte; `cargo test` pins the same vector as `tests/webauthn.test.ts`.

## Verified

Against the production database on 2026-10-26: **20 credentials, 13 users, 20 exported, 0 failures**,
all ES256; every exported public key was then parsed by `@simplewebauthn/server`'s
`decodeCredentialPublicKey` and came back as EC2 / P-256 / ES256, which is the decode the Worker
performs on each assertion. All 20 rows carry `transports: null`, so the exported documents say `[]`.

What this cannot prove without a device: that a *signature* verifies, and that the handle the
authenticator stored equals the derived one. Both are covered by the cutover checklist item "one real
device passkey sign-in against the new instance" — a mismatch fails closed with
`400 invalid_webauthn_authentication`.

## Not in CI

The repository's pipeline is Node-only. Run `cargo test` here before using the tool; the build needs
OpenSSL (`PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig` on macOS).
