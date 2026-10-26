import type { SigningKeyRow, SigningKeyStore, KeySlot } from './jwks';

const SELECT_KEYS = 'SELECT id, kid, alg, public_jwk, private_jwk FROM jwks_keys';

export class D1SigningKeyStore implements SigningKeyStore {
  constructor(private readonly db: D1Database) {}

  async list(): Promise<SigningKeyRow[]> {
    const { results } = await this.db.prepare(SELECT_KEYS).all<{
      id: KeySlot;
      kid: string;
      alg: string;
      public_jwk: string;
      private_jwk: string;
    }>();
    return results.map((row) => ({
      slot: row.id,
      kid: row.kid,
      alg: row.alg,
      publicJwk: row.public_jwk,
      privateJwk: row.private_jwk,
    }));
  }

  /** One batch, so a rotation can never be observed half applied. */
  async rotate(next: SigningKeyRow): Promise<void> {
    await this.db.batch([
      this.db.prepare("DELETE FROM jwks_keys WHERE id = 'CURRENT'"),
      this.db.prepare("UPDATE jwks_keys SET id = 'CURRENT' WHERE id = 'STANDBY'"),
      this.db
        .prepare('INSERT INTO jwks_keys (id, kid, alg, public_jwk, private_jwk) VALUES (?1, ?2, ?3, ?4, ?5)')
        .bind(next.slot, next.kid, next.alg, next.publicJwk, next.privateJwk),
    ]);
  }

  async insert(row: SigningKeyRow): Promise<void> {
    await this.db
      .prepare('INSERT INTO jwks_keys (id, kid, alg, public_jwk, private_jwk) VALUES (?1, ?2, ?3, ?4, ?5)')
      .bind(row.slot, row.kid, row.alg, row.publicJwk, row.privateJwk)
      .run();
  }
}
