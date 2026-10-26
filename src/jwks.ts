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
}

const SLOT_ORDER: readonly KeySlot[] = ['CURRENT', 'STANDBY'];

function toPublicJwk(jwk: Ed25519PrivateJwk): Ed25519PublicJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
}

function toPrivateJwk(jwk: Ed25519PrivateJwk): Ed25519PrivateJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d };
}

/** Bootstraps any missing slot, mirroring `bootstrap_keys()` in the legacy server. */
export async function ensureSigningKeys(store: SigningKeyStore): Promise<SigningKeyRow[]> {
  // Snapshot: a store may hand back a live array, and we append to this copy below.
  let rows = [...(await store.list())];
  for (const slot of SLOT_ORDER) {
    if (rows.some((row) => row.slot === slot)) continue;
    const pair = await generateKeyPair();
    const row: SigningKeyRow = {
      slot,
      kid: uuidv4(),
      alg: 'EdDSA',
      publicJwk: JSON.stringify(toPublicJwk(pair.privateJwk)),
      privateJwk: JSON.stringify(toPrivateJwk(pair.privateJwk)),
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

/** `GET /jwks` body: public keys only, CURRENT before STANDBY, exactly as legacy emitted. */
export async function publicJwksBody(store: SigningKeyStore): Promise<{ keys: Ed25519PublicJwk[] }> {
  const rows = await ensureSigningKeys(store);
  const keys = SLOT_ORDER.flatMap((slot) =>
    rows.filter((row) => row.slot === slot).map((row) => JSON.parse(row.publicJwk) as Ed25519PublicJwk),
  );
  return { keys };
}

/** `GET /admin/jwks` body: slot labels plus public material, never private material. */
export async function adminJwksBody(store: SigningKeyStore): Promise<{ keys: Array<{ slot: string; public_jwk: Ed25519PublicJwk }> }> {
  const rows = await ensureSigningKeys(store);
  const keys = SLOT_ORDER.flatMap((slot) =>
    rows
      .filter((row) => row.slot === slot)
      .map((row) => ({ slot: row.slot, public_jwk: JSON.parse(row.publicJwk) as Ed25519PublicJwk })),
  );
  return { keys };
}
