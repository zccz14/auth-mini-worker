import { uuidv4 } from './crypto/tokens';
import type { Ed25519ChallengeRow, Ed25519CredentialRow, Ed25519Store } from './stores';

interface CredentialShape {
  id: string;
  user_id: string;
  name: string;
  public_key: string;
  last_used_at: string | null;
  created_at: string;
}

function toRow(row: CredentialShape): Ed25519CredentialRow {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    publicKey: row.public_key,
    lastUsedAt: row.last_used_at,
    createdAt: row.created_at,
  };
}

const CREDENTIAL_COLUMNS = 'id, user_id, name, public_key, last_used_at, created_at';

export class D1Ed25519Store implements Ed25519Store {
  constructor(private readonly db: D1Database) {}

  async credentialIdsByPublicKey(publicKey: string): Promise<string[]> {
    const { results } = await this.db
      .prepare('SELECT id FROM ed25519_credentials WHERE public_key = ?1 LIMIT 2')
      .bind(publicKey)
      .all<{ id: string }>();
    return results.map((row) => row.id);
  }

  async credentialById(id: string): Promise<Ed25519CredentialRow | null> {
    const row = await this.db
      .prepare(`SELECT ${CREDENTIAL_COLUMNS} FROM ed25519_credentials WHERE id = ?1 LIMIT 1`)
      .bind(id)
      .first<CredentialShape>();
    return row ? toRow(row) : null;
  }

  async listByUser(userId: string): Promise<Ed25519CredentialRow[]> {
    const { results } = await this.db
      .prepare(`SELECT ${CREDENTIAL_COLUMNS} FROM ed25519_credentials WHERE user_id = ?1 ORDER BY created_at ASC, id ASC`)
      .bind(userId)
      .all<CredentialShape>();
    return results.map(toRow);
  }

  async create(userId: string, name: string, publicKey: string, now: string): Promise<Ed25519CredentialRow | null> {
    const existing = await this.credentialIdsByPublicKey(publicKey);
    if (existing.length > 0) return null;
    const id = uuidv4();
    await this.db
      .prepare('INSERT INTO ed25519_credentials (id, user_id, name, public_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5)')
      .bind(id, userId, name, publicKey, now)
      .run();
    return this.credentialById(id);
  }

  async updateName(id: string, userId: string, name: string): Promise<Ed25519CredentialRow | null> {
    await this.db.prepare('UPDATE ed25519_credentials SET name = ?1 WHERE id = ?2 AND user_id = ?3').bind(name, id, userId).run();
    const row = await this.credentialById(id);
    return row && row.userId === userId ? row : null;
  }

  async remove(id: string, userId: string): Promise<boolean> {
    const result = await this.db.prepare('DELETE FROM ed25519_credentials WHERE id = ?1 AND user_id = ?2').bind(id, userId).run();
    return (result.meta.changes ?? 0) > 0;
  }

  async createChallenge(requestId: string, credentialId: string, challenge: string, expiresAt: string, now: string): Promise<void> {
    await this.db
      .prepare('INSERT INTO ed25519_challenges (request_id, credential_id, challenge, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5)')
      .bind(requestId, credentialId, challenge, expiresAt, now)
      .run();
  }

  async findChallenge(requestId: string): Promise<Ed25519ChallengeRow | null> {
    const row = await this.db
      .prepare('SELECT request_id, credential_id, challenge, expires_at, consumed_at FROM ed25519_challenges WHERE request_id = ?1 LIMIT 1')
      .bind(requestId)
      .first<{ request_id: string; credential_id: string; challenge: string; expires_at: string; consumed_at: string | null }>();
    if (!row) return null;
    return {
      requestId: row.request_id,
      credentialId: row.credential_id,
      challenge: row.challenge,
      expiresAt: row.expires_at,
      consumedAt: row.consumed_at,
    };
  }

  async consumeChallenge(requestId: string, now: string): Promise<boolean> {
    const result = await this.db
      .prepare('UPDATE ed25519_challenges SET consumed_at = ?1 WHERE request_id = ?2 AND consumed_at IS NULL AND expires_at > ?1')
      .bind(now, requestId)
      .run();
    return (result.meta.changes ?? 0) === 1;
  }

  async touchLastUsed(credentialId: string, now: string): Promise<void> {
    await this.db.prepare('UPDATE ed25519_credentials SET last_used_at = ?1 WHERE id = ?2').bind(now, credentialId).run();
  }
}
