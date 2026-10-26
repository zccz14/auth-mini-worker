import { describe, expect, it } from 'vitest';
import type { SigningKeyRow, SigningKeyStore } from '../src/jwks';
import { adminJwksBody, currentSigningKey, ensureSigningKeys, publicJwksBody } from '../src/jwks';

class MemoryStore implements SigningKeyStore {
  rows: SigningKeyRow[] = [];

  async list(): Promise<SigningKeyRow[]> {
    return this.rows;
  }

  async insert(row: SigningKeyRow): Promise<void> {
    this.rows.push(row);
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
      expect(key).toEqual({ kty: 'OKP', crv: 'Ed25519', x: expect.any(String) });
      expect('d' in key).toBe(false);
    }
    const admin = await adminJwksBody(store);
    expect(admin.keys.map((entry) => entry.slot)).toEqual(['CURRENT', 'STANDBY']);
  });

  it('hands the current private key out for signing only when asked', async () => {
    const store = new MemoryStore();
    const key = await currentSigningKey(store);
    expect(key.privateJwk.d).toHaveLength(43);
    expect(key.publicJwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: key.privateJwk.x });
  });
});
