import { parsePasskey } from './webauthn';
import type {
  AppMetaStore,
  CredentialStore,
  EmailOtpRecord,
  EmailOtpStore,
  SessionRecord,
  SessionRow,
  SessionStore,
  UserStore,
} from './stores';
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

  async findEmail(userId: string): Promise<string | null> {
    const row = await this.db.prepare('SELECT email FROM users WHERE id = ?1 LIMIT 1').bind(userId).first<{ email: string | null }>();
    return row?.email ?? null;
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

const SESSION_COLUMNS =
  'id, user_id, refresh_token_hash, auth_method, source_auth_method, audience, ip, user_agent, expires_at, created_at';

interface SessionRowShape {
  id: string;
  user_id: string;
  refresh_token_hash: string;
  auth_method: string;
  source_auth_method: string | null;
  audience: string;
  ip: string | null;
  user_agent: string | null;
  expires_at: string;
  created_at: string;
}

function toSessionRow(row: SessionRowShape): SessionRow {
  let audiences: string[] = [];
  try {
    const parsed: unknown = JSON.parse(row.audience);
    if (Array.isArray(parsed)) audiences = parsed.filter((value): value is string => typeof value === 'string');
  } catch {
    // legacy rows could hold a bare string; treat it as a single audience
    if (row.audience.length > 0) audiences = [row.audience];
  }
  return {
    id: row.id,
    userId: row.user_id,
    refreshTokenHash: row.refresh_token_hash,
    authMethod: row.auth_method,
    sourceAuthMethod: row.source_auth_method,
    audiences,
    ip: row.ip,
    userAgent: row.user_agent,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
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

  async find(id: string): Promise<SessionRow | null> {
    const row = await this.db
      .prepare(`SELECT ${SESSION_COLUMNS} FROM sessions WHERE id = ?1 LIMIT 1`)
      .bind(id)
      .first<SessionRowShape>();
    return row ? toSessionRow(row) : null;
  }

  async rotate(id: string, expectedHash: string, nextHash: string, nextExpiresAt: string, now: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE sessions SET refresh_token_hash = ?1, expires_at = ?2
         WHERE id = ?3 AND refresh_token_hash = ?4 AND expires_at > ?5`,
      )
      .bind(nextHash, nextExpiresAt, id, expectedHash, now)
      .run();
    return (result.meta.changes ?? 0) === 1;
  }

  async expire(id: string, now: string): Promise<void> {
    await this.db.prepare('UPDATE sessions SET expires_at = ?1 WHERE id = ?2 AND expires_at > ?1').bind(now, id).run();
  }

  async listActive(userId: string, now: string): Promise<SessionRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT ${SESSION_COLUMNS} FROM sessions WHERE user_id = ?1 AND expires_at > ?2
         ORDER BY created_at ASC, id ASC`,
      )
      .bind(userId, now)
      .all<SessionRowShape>();
    return results.map(toSessionRow);
  }
}

export class D1CredentialStore implements CredentialStore {
  constructor(private readonly db: D1Database) {}

  async listWebauthn(userId: string): Promise<Array<Record<string, unknown>>> {
    const { results } = await this.db
      .prepare(
        `SELECT credential_id, passkey_json, rp_id, last_used_at, created_at FROM webauthn_credentials
         WHERE user_id = ?1 ORDER BY created_at ASC, credential_id ASC`,
      )
      .bind(userId)
      .all<{
        credential_id: string;
        passkey_json: string;
        rp_id: string;
        last_used_at: string | null;
        created_at: string;
      }>();
    return results.map((row) => {
      // A row whose stored shape we do not recognise still belongs to the user; only its
      // transports are unknown, so the listing degrades instead of disappearing.
      const stored = parsePasskey(row.passkey_json);
      return {
        id: row.credential_id,
        credential_id: row.credential_id,
        transports: stored?.transports ?? [],
        rp_id: row.rp_id,
        last_used_at: row.last_used_at,
        created_at: row.created_at,
      };
    });
  }

  async listEd25519(userId: string): Promise<Array<Record<string, unknown>>> {
    const { results } = await this.db
      .prepare(
        `SELECT id, name, public_key, last_used_at, created_at FROM ed25519_credentials
         WHERE user_id = ?1 ORDER BY created_at ASC, id ASC`,
      )
      .bind(userId)
      .all<{ id: string; name: string; public_key: string; last_used_at: string | null; created_at: string }>();
    return results.map((row) => ({
      id: row.id,
      name: row.name,
      public_key: row.public_key,
      last_used_at: row.last_used_at,
      created_at: row.created_at,
    }));
  }
}
