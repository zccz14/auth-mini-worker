import { describe, expect, it } from 'vitest';
import type { SigningKeyRow, SigningKeyStore } from '../src/jwks';
import { adminJwksBody, currentSigningKey, ensureSigningKeys, publicJwksBody, rotateSigningKeys } from '../src/jwks';

class MemoryStore implements SigningKeyStore {
  rows: SigningKeyRow[] = [];

  async list(): Promise<SigningKeyRow[]> {
    return this.rows;
  }

  async insert(row: SigningKeyRow): Promise<void> {
    this.rows.push(row);
  }

  async rotate(next: SigningKeyRow): Promise<void> {
    const standby = this.rows.find((row) => row.slot === 'STANDBY');
    if (!standby) throw new Error('missing_standby_key');
    this.rows = this.rows.filter((row) => row.slot !== 'CURRENT');
    standby.slot = 'CURRENT';
    this.rows.push(next);
  }
}

describe('signing keys', () => {
  it('bootstraps CURRENT and STANDBY once', async () => {
    const store = new MemoryStore();
    await ensureSigningKeys(store);
    await ensureSigningKeys(store);
    expect(store.rows.map((row) => row.slot)).toEqual(['CURRENT', 'STANDBY']);
    expect(new Set(store.rows.map((row) => row.kid)).size).toBe(2);
    expect(store.rows.every((row) => row.alg === 'EdDSA')).toBe(true);
  });

  it('publishes public material only, CURRENT first', async () => {
    const store = new MemoryStore();
    const body = await publicJwksBody(store);

    expect(body.keys).toHaveLength(2);
    for (const key of body.keys) {
      expect(key).toEqual({
        alg: 'EdDSA',
        crv: 'Ed25519',
        kid: expect.any(String),
        kty: 'OKP',
        use: 'sig',
        x: expect.any(String),
      });
      expect('d' in key).toBe(false);
    }
    const admin = await adminJwksBody(store);
    expect(admin.keys.map((entry) => entry.slot)).toEqual(['CURRENT', 'STANDBY']);
  });

  it('publishes the kid that a token header names', async () => {
    const store = new MemoryStore();
    const key = await currentSigningKey(store);
    const body = await publicJwksBody(store);

    expect(body.keys.map((published) => published.kid)).toContain(key.kid);
  });

  it('stamps the kid onto rows stored before it was part of the JWK', async () => {
    const store = new MemoryStore();
    await ensureSigningKeys(store);
    store.rows = store.rows.map((row) => ({
      ...row,
      publicJwk: JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: JSON.parse(row.publicJwk).x }),
    }));

    const body = await publicJwksBody(store);
    expect(body.keys.map((key) => key.kid)).toEqual(store.rows.map((row) => row.kid));
  });

  it('hands the current private key out for signing only when asked', async () => {
    const store = new MemoryStore();
    const key = await currentSigningKey(store);
    expect(key.privateJwk.d).toHaveLength(43);
    expect(key.publicJwk).toEqual({
      alg: 'EdDSA',
      crv: 'Ed25519',
      kid: key.kid,
      kty: 'OKP',
      use: 'sig',
      x: key.privateJwk.x,
    });
  });
});

describe('rotation', () => {
  it('promotes STANDBY to CURRENT and mints a fresh STANDBY', async () => {
    const store = new MemoryStore();
    const before = await publicJwksBody(store);
    const [oldCurrent, oldStandby] = before.keys;

    const rotated = await rotateSigningKeys(store);
    expect(rotated.keys.map((entry) => entry.slot)).toEqual(['CURRENT', 'STANDBY']);
    expect(rotated.keys[0]!.public_jwk).toEqual(oldStandby);
    expect(rotated.keys[1]!.public_jwk).not.toEqual(oldCurrent);
    expect(rotated.keys[1]!.public_jwk).not.toEqual(oldStandby);

    const after = await publicJwksBody(store);
    expect(after.keys).toHaveLength(2);
    expect(after.keys[0]).toEqual(oldStandby);
    expect(after.keys).not.toContainEqual(oldCurrent);
    expect(store.rows.map((row) => row.slot).sort()).toEqual(['CURRENT', 'STANDBY']);
  });

  it('self-heals a missing STANDBY slot before promoting it', async () => {
    const store = new MemoryStore();
    await ensureSigningKeys(store);
    store.rows = store.rows.filter((row) => row.slot === 'CURRENT');

    const rotated = await rotateSigningKeys(store);
    expect(rotated.keys.map((entry) => entry.slot)).toEqual(['CURRENT', 'STANDBY']);
    expect(store.rows.map((row) => row.slot).sort()).toEqual(['CURRENT', 'STANDBY']);
  });
});
