import type { RemoteLoginRow, RemoteLoginStore } from './stores';

interface RowShape {
  id: string;
  redirect_uri: string | null;
  audience: string;
  expires_at: string;
  created_at: string;
  status: string;
  approved_user_id: string | null;
}

function parseAudiences(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

function toRow(row: RowShape): RemoteLoginRow {
  return {
    requestId: row.id,
    redirectUri: row.redirect_uri,
    audiences: parseAudiences(row.audience),
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    status: row.status,
    approvedUserId: row.approved_user_id,
  };
}

const COLUMNS = 'id, redirect_uri, audience, expires_at, created_at, status, approved_user_id';

export class D1RemoteLoginStore implements RemoteLoginStore {
  constructor(private readonly db: D1Database) {}

  async create(row: {
    requestId: string;
    exchangeCodeHash: string;
    confirmationCodeHash: string;
    redirectUri: string | null;
    audiences: readonly string[];
    expiresAt: string;
    now: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO remote_login_requests
         (id, exchange_code_hash, confirmation_code_hash, redirect_uri, audience, status, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)`,
      )
      .bind(row.requestId, row.exchangeCodeHash, row.confirmationCodeHash, row.redirectUri, JSON.stringify([...row.audiences]), row.expiresAt, row.now)
      .run();
  }

  async findIdByConfirmationCode(confirmationCodeHash: string, now: string): Promise<string | null> {
    const row = await this.db
      .prepare(
        `SELECT id FROM remote_login_requests
         WHERE confirmation_code_hash = ?1 AND status = 'pending' AND approved_user_id IS NULL AND expires_at > ?2
         LIMIT 1`,
      )
      .bind(confirmationCodeHash, now)
      .first<{ id: string }>();
    return row?.id ?? null;
  }

  async claim(requestId: string, userId: string, confirmationCodeHash: string, now: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE remote_login_requests SET approved_user_id = ?1
         WHERE id = ?2 AND confirmation_code_hash = ?3 AND status = 'pending'
           AND approved_user_id IS NULL AND expires_at > ?4`,
      )
      .bind(userId, requestId, confirmationCodeHash, now)
      .run();
    return (result.meta.changes ?? 0) === 1;
  }

  async expireStale(now: string): Promise<void> {
    await this.db.prepare("UPDATE remote_login_requests SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?1").bind(now).run();
  }

  async listPending(userId: string, now: string): Promise<RemoteLoginRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT ${COLUMNS} FROM remote_login_requests
         WHERE approved_user_id = ?1 AND status = 'pending' AND expires_at > ?2
         ORDER BY created_at ASC, id ASC`,
      )
      .bind(userId, now)
      .all<RowShape>();
    return results.map(toRow);
  }

  async summary(requestId: string, userId: string): Promise<RemoteLoginRow | null> {
    const row = await this.db
      .prepare(`SELECT ${COLUMNS} FROM remote_login_requests WHERE id = ?1 AND approved_user_id = ?2 AND status = 'pending' LIMIT 1`)
      .bind(requestId, userId)
      .first<RowShape>();
    return row ? toRow(row) : null;
  }

  async decide(requestId: string, userId: string, status: 'approved' | 'denied', now: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE remote_login_requests
         SET status = ?1, ${status === 'approved' ? 'approved_at' : 'denied_at'} = ?2
         WHERE id = ?3 AND approved_user_id = ?4 AND status = 'pending' AND expires_at > ?2`,
      )
      .bind(status, now, requestId, userId)
      .run();
    return (result.meta.changes ?? 0) === 1;
  }

  async findApproved(requestId: string, exchangeCodeHash: string, now: string): Promise<{ userId: string; audiences: string[] } | null> {
    const row = await this.db
      .prepare(
        `SELECT approved_user_id, audience FROM remote_login_requests
         WHERE id = ?1 AND exchange_code_hash = ?2 AND status = 'approved' AND expires_at > ?3`,
      )
      .bind(requestId, exchangeCodeHash, now)
      .first<{ approved_user_id: string | null; audience: string }>();
    if (!row?.approved_user_id) return null;
    return { userId: row.approved_user_id, audiences: parseAudiences(row.audience) };
  }

  async consume(requestId: string, exchangeCodeHash: string, now: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE remote_login_requests SET status = 'consumed', consumed_at = ?1
         WHERE id = ?2 AND exchange_code_hash = ?3 AND status = 'approved' AND expires_at > ?1`,
      )
      .bind(now, requestId, exchangeCodeHash)
      .run();
    return (result.meta.changes ?? 0) === 1;
  }
}
