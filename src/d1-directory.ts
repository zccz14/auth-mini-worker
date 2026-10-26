import type { DirectoryStore, UserSummary } from './stores';

export class D1DirectoryStore implements DirectoryStore {
  constructor(private readonly db: D1Database) {}

  async tokenStatus(): Promise<{ configured: boolean; createdAt: string | null }> {
    const row = await this.db.prepare('SELECT created_at FROM user_directory_token WHERE id = 1').first<{ created_at: string }>();
    return { configured: row !== null, createdAt: row?.created_at ?? null };
  }

  async rotateToken(tokenHash: string): Promise<string> {
    const createdAt = new Date().toISOString();
    await this.db
      .prepare(
        `INSERT INTO user_directory_token (id, token_hash, created_at) VALUES (1, ?1, ?2)
         ON CONFLICT(id) DO UPDATE SET token_hash = excluded.token_hash, created_at = excluded.created_at`,
      )
      .bind(tokenHash, createdAt)
      .run();
    return createdAt;
  }

  async clearToken(): Promise<void> {
    await this.db.prepare('DELETE FROM user_directory_token').run();
  }

  async matchesTokenHash(tokenHash: string): Promise<boolean> {
    const row = await this.db
      .prepare('SELECT 1 AS hit FROM user_directory_token WHERE id = 1 AND token_hash = ?1')
      .bind(tokenHash)
      .first<{ hit: number }>();
    return row !== null;
  }

  async listUserIds(): Promise<string[]> {
    const { results } = await this.db.prepare('SELECT id FROM users ORDER BY id').all<{ id: string }>();
    return results.map((row) => row.id);
  }

  /**
   * `now` is passed in rather than compared against CURRENT_TIMESTAMP: `expires_at` is RFC 3339
   * with a `T` and a `Z`, and SQLite's CURRENT_TIMESTAMP renders as `YYYY-MM-DD HH:MM:SS`, so a
   * string comparison between the two is decided by the separator, not by the date. The legacy
   * query did exactly that, which made the active-session count meaningless.
   */
  async listUsers(now: string): Promise<UserSummary[]> {
    const { results } = await this.db
      .prepare(
        `SELECT users.id AS id,
                users.email AS email,
                users.email_verified_at AS email_verified_at,
                users.created_at AS created_at,
                COUNT(DISTINCT sessions.id) AS active_session_count,
                COUNT(DISTINCT webauthn_credentials.credential_id) AS passkey_count,
                COUNT(DISTINCT ed25519_credentials.id) AS ed25519_count
         FROM users
         LEFT JOIN sessions ON sessions.user_id = users.id AND sessions.expires_at > ?1
         LEFT JOIN webauthn_credentials ON webauthn_credentials.user_id = users.id
         LEFT JOIN ed25519_credentials ON ed25519_credentials.user_id = users.id
         GROUP BY users.id
         ORDER BY users.created_at DESC, users.id ASC`,
      )
      .bind(now)
      .all<{
        id: string;
        email: string | null;
        email_verified_at: string | null;
        created_at: string;
        active_session_count: number;
        passkey_count: number;
        ed25519_count: number;
      }>();
    return results.map((row) => ({
      id: row.id,
      email: row.email,
      emailVerifiedAt: row.email_verified_at,
      createdAt: row.created_at,
      activeSessionCount: row.active_session_count,
      passkeyCount: row.passkey_count,
      ed25519Count: row.ed25519_count,
    }));
  }
}
