import type { EmailOtpRecord, EmailOtpStore, AppMetaStore, SessionRecord, SessionStore, UserStore } from './email/stores';
import type { SmtpConfig, SmtpConfigStore } from './mail/config';
import { uuidv4 } from './crypto/tokens';

/** `INSERT OR IGNORE` on users.email, then the id — the unique index is the race guard. */
export class D1UserStore implements UserStore {
  constructor(private readonly db: D1Database) {}

  async ensureByEmail(email: string, now: string): Promise<string> {
    await this.db
      .prepare('INSERT OR IGNORE INTO users (id, email, email_verified_at) VALUES (?1, ?2, ?3)')
      .bind(uuidv4(), email, now)
      .run();
    await this.db
      .prepare('UPDATE users SET email_verified_at = ?1 WHERE email = ?2 AND email_verified_at IS NULL')
      .bind(now, email)
      .run();
    const id = await this.findIdByEmail(email);
    if (id === null) throw new Error('user_not_found_after_insert');
    return id;
  }

  async findIdByEmail(email: string): Promise<string | null> {
    const row = await this.db.prepare('SELECT id FROM users WHERE email = ?1 LIMIT 1').bind(email).first<{ id: string }>();
    return row?.id ?? null;
  }

  async isAdmin(userId: string): Promise<boolean> {
    const row = await this.db
      .prepare("SELECT admin_user_id FROM app_meta WHERE id = 'APP' LIMIT 1")
      .first<{ admin_user_id: string | null }>();
    return row?.admin_user_id === userId && userId.length > 0;
  }
}

export class D1EmailOtpStore implements EmailOtpStore {
  constructor(private readonly db: D1Database) {}

  async upsert(email: string, codeHash: string, expiresAt: string): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO email_otps (email, code_hash, expires_at, consumed_at) VALUES (?1, ?2, ?3, NULL)
         ON CONFLICT(email) DO UPDATE SET code_hash = excluded.code_hash,
                                          expires_at = excluded.expires_at,
                                          consumed_at = NULL`,
      )
      .bind(email, codeHash, expiresAt)
      .run();
  }

  async invalidate(email: string): Promise<void> {
    await this.db.prepare('UPDATE email_otps SET consumed_at = ?1 WHERE email = ?2 AND consumed_at IS NULL').bind(new Date().toISOString(), email).run();
  }

  async consume(email: string, codeHash: string, now: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE email_otps SET consumed_at = ?1
         WHERE email = ?2 AND code_hash = ?3 AND consumed_at IS NULL AND expires_at > ?1`,
      )
      .bind(now, email, codeHash)
      .run();
    return (result.meta.changes ?? 0) === 1;
  }

  async find(email: string): Promise<EmailOtpRecord | null> {
    const row = await this.db
      .prepare('SELECT code_hash, expires_at, consumed_at FROM email_otps WHERE email = ?1 LIMIT 1')
      .bind(email)
      .first<{ code_hash: string; expires_at: string; consumed_at: string | null }>();
    if (!row) return null;
    return { codeHash: row.code_hash, expiresAt: row.expires_at, consumedAt: row.consumed_at };
  }
}

export class D1SessionStore implements SessionStore {
  constructor(private readonly db: D1Database) {}

  async insert(session: SessionRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO sessions (id, user_id, refresh_token_hash, auth_method, source_auth_method, audience, ip, user_agent, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
      )
      .bind(
        session.id,
        session.userId,
        session.refreshTokenHash,
        session.authMethod,
        session.sourceAuthMethod,
        JSON.stringify([...session.audiences]),
        session.ip,
        session.userAgent,
        session.expiresAt,
      )
      .run();
  }
}

export class D1AppMetaStore implements AppMetaStore {
  constructor(private readonly db: D1Database) {}

  /** Seeds the single APP row on first use, the way `ensure_app_meta` did at startup. */
  async readIssuer(): Promise<string> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO app_meta (id, issuer, rp_id, brand_name, brand_background_image)
         VALUES ('APP', 'http://localhost:7777', 'localhost', 'auth-mini', '')`,
      )
      .run();
    const row = await this.db.prepare("SELECT issuer FROM app_meta WHERE id = 'APP' LIMIT 1").first<{ issuer: string }>();
    if (!row) throw new Error('app_meta_missing');
    return row.issuer;
  }
}

export class D1SmtpConfigStore implements SmtpConfigStore {
  constructor(private readonly db: D1Database) {}

  async listActive(): Promise<SmtpConfig[]> {
    const { results } = await this.db
      .prepare(
        `SELECT id, host, port, username, password, from_email, from_name, secure, weight
         FROM smtp_configs WHERE is_active = 1 ORDER BY id ASC`,
      )
      .all<{
        id: number;
        host: string;
        port: number;
        username: string;
        password: string;
        from_email: string;
        from_name: string;
        secure: number;
        weight: number;
      }>();
    return results.map((row) => ({
      id: row.id,
      host: row.host,
      port: row.port,
      username: row.username,
      password: row.password,
      fromEmail: row.from_email,
      fromName: row.from_name,
      secure: row.secure === 1,
      weight: row.weight,
    }));
  }
}
