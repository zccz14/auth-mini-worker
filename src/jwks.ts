import type { Ed25519PrivateJwk, Ed25519PublicJwk } from './crypto/ed25519';
import { generateKeyPair } from './crypto/ed25519';
import { uuidv4 } from './crypto/tokens';

export type KeySlot = 'CURRENT' | 'STANDBY';

/** One row of `jwks_keys`; `publicJwk`/`privateJwk` hold the serialized JWK JSON, as legacy did. */
export interface SigningKeyRow {
  slot: KeySlot;
  kid: string;
  alg: string;
  publicJwk: string;
  privateJwk: string;
}

export interface SigningKeyStore {
  list(): Promise<SigningKeyRow[]>;
  insert(row: SigningKeyRow): Promise<void>;
  /**
   * Atomic promotion: drop CURRENT, move STANDBY into CURRENT, insert `next` as STANDBY.
   * Must run as one batch — a half-applied rotation would leave an instance that cannot verify
   * its own recently issued tokens and cannot sign new ones.
   */
  rotate(next: SigningKeyRow): Promise<void>;
}

const SLOT_ORDER: readonly KeySlot[] = ['CURRENT', 'STANDBY'];

/**
 * The exact six members legacy wrote into `jwks_keys.public_jwk`, in legacy's order.
 *
 * `kid` is the point: a token header names its key, so a verifier that fetches `/jwks` has to be
 * able to match on it. Publishing only `kty`/`crv`/`x` left every kid-based verifier — the React
 * provider and `auth-mini-axum` among them — unable to find the key at all.
 */
function toPublicJwk(jwk: Ed25519PrivateJwk, kid: string): Ed25519PublicJwk {
  return { alg: 'EdDSA', crv: 'Ed25519', kid, kty: 'OKP', use: 'sig', x: jwk.x };
}

function toPrivateJwk(jwk: Ed25519PrivateJwk, kid: string): Ed25519PrivateJwk {
  return { alg: 'EdDSA', crv: 'Ed25519', kid, kty: 'OKP', use: 'sig', x: jwk.x, d: jwk.d };
}

/**
 * Rows written before `kid` was stamped into the JWK still have to answer correctly, so the
 * serializers rebuild the legacy shape from the row instead of trusting the stored JSON.
 */
function storedPublicJwk(row: SigningKeyRow): Ed25519PublicJwk {
  const parsed = JSON.parse(row.publicJwk) as Partial<Ed25519PublicJwk>;
  if (parsed.kid === row.kid && parsed.alg === 'EdDSA' && parsed.use === 'sig' && parsed.kty === 'OKP') {
    return parsed as Ed25519PublicJwk;
  }
  return { alg: 'EdDSA', crv: 'Ed25519', kid: row.kid, kty: 'OKP', use: 'sig', x: parsed.x as string };
}

/** Bootstraps any missing slot, mirroring `bootstrap_keys()` in the legacy server. */
export async function ensureSigningKeys(store: SigningKeyStore): Promise<SigningKeyRow[]> {
  // Snapshot: a store may hand back a live array, and we append to this copy below.
  let rows = [...(await store.list())];
  for (const slot of SLOT_ORDER) {
    if (rows.some((row) => row.slot === slot)) continue;
    const pair = await generateKeyPair();
    const row_kid = uuidv4();
    const row: SigningKeyRow = {
      slot,
      kid: row_kid,
      alg: 'EdDSA',
      publicJwk: JSON.stringify(toPublicJwk(pair.privateJwk, row_kid)),
      privateJwk: JSON.stringify(toPrivateJwk(pair.privateJwk, row_kid)),
    };
    await store.insert(row);
    rows = [...rows, row];
  }
  return rows;
}

export interface ActiveSigningKey {
  kid: string;
  privateJwk: Ed25519PrivateJwk;
  publicJwk: Ed25519PublicJwk;
}

export async function currentSigningKey(store: SigningKeyStore): Promise<ActiveSigningKey> {
  const rows = await ensureSigningKeys(store);
  const row = rows.find((candidate) => candidate.slot === 'CURRENT');
  if (!row) throw new Error('missing_current_key');
  return {
    kid: row.kid,
    privateJwk: JSON.parse(row.privateJwk) as Ed25519PrivateJwk,
    publicJwk: JSON.parse(row.publicJwk) as Ed25519PublicJwk,
  };
}

/** Public half of the key with this `kid`, from either slot — legacy `key_by_kid`. */
export async function verifyingKeyByKid(
  store: SigningKeyStore,
  kid: string,
): Promise<{ kid: string; publicJwk: Ed25519PublicJwk } | null> {
  const rows = await ensureSigningKeys(store);
  const row = rows.find((candidate) => candidate.kid === kid);
  if (!row) return null;
  return { kid: row.kid, publicJwk: JSON.parse(row.publicJwk) as Ed25519PublicJwk };
}

/**
 * Port of `rotate_keys`: STANDBY becomes CURRENT, a fresh key becomes STANDBY.
 *
 * The new CURRENT is one downstream caches already have, which is the point of keeping a
 * published spare. The old CURRENT disappears, so tokens it signed stop verifying — that is the
 * legacy behaviour, and it bounds the blast radius to the access-token lifetime.
 */
export async function rotateSigningKeys(
  store: SigningKeyStore,
): Promise<{ keys: Array<{ slot: string; public_jwk: Ed25519PublicJwk }> }> {
  const rows = await ensureSigningKeys(store);
  const standby = rows.find((row) => row.slot === 'STANDBY');
  if (!standby) throw new Error('missing_standby_key');

  const pair = await generateKeyPair();
  const nextKid = uuidv4();
  const next: SigningKeyRow = {
    slot: 'STANDBY',
    kid: nextKid,
    alg: 'EdDSA',
    publicJwk: JSON.stringify(toPublicJwk(pair.privateJwk, nextKid)),
    privateJwk: JSON.stringify(toPrivateJwk(pair.privateJwk, nextKid)),
  };
  await store.rotate(next);

  return {
    keys: [
      { slot: 'CURRENT', public_jwk: storedPublicJwk(standby) },
      { slot: 'STANDBY', public_jwk: storedPublicJwk(next) },
    ],
  };
}

/** `GET /jwks` body: public keys only, CURRENT before STANDBY, exactly as legacy emitted. */
export async function publicJwksBody(store: SigningKeyStore): Promise<{ keys: Ed25519PublicJwk[] }> {
  const rows = await ensureSigningKeys(store);
  const keys = SLOT_ORDER.flatMap((slot) =>
    rows.filter((row) => row.slot === slot).map(storedPublicJwk),
  );
  return { keys };
}

/** `GET /admin/jwks` body: slot labels plus public material, never private material. */
export async function adminJwksBody(store: SigningKeyStore): Promise<{ keys: Array<{ slot: string; public_jwk: Ed25519PublicJwk }> }> {
  const rows = await ensureSigningKeys(store);
  const keys = SLOT_ORDER.flatMap((slot) =>
    rows
      .filter((row) => row.slot === slot)
      .map((row) => ({ slot: row.slot, public_jwk: storedPublicJwk(row) })),
  );
  return { keys };
}
