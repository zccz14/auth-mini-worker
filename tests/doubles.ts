import type { EmailOtpRecord, EmailOtpStore, SessionRecord, SessionRow, SessionStore, UserStore } from '../src/stores';
import type { SigningKeyRow, SigningKeyStore } from '../src/jwks';

export class MemoryOtpStore implements EmailOtpStore {
  rows = new Map<string, EmailOtpRecord>();

  async upsert(email: string, codeHash: string, expiresAt: string): Promise<void> {
    this.rows.set(email, { codeHash, expiresAt, consumedAt: null });
  }

  async invalidate(email: string): Promise<void> {
    const row = this.rows.get(email);
    if (row) row.consumedAt = new Date().toISOString();
  }

  async consume(email: string, codeHash: string, now: string): Promise<boolean> {
    const row = this.rows.get(email);
    if (!row || row.consumedAt !== null || row.expiresAt <= now || row.codeHash !== codeHash) return false;
    row.consumedAt = now;
    return true;
  }

  async find(email: string): Promise<EmailOtpRecord | null> {
    return this.rows.get(email) ?? null;
  }
}

export class MemoryUserStore implements UserStore {
  byEmail = new Map<string, string>();
  byId = new Map<string, string>();
  adminId: string | null = null;

  async ensureByEmail(email: string, _now: string): Promise<string> {
    const existing = this.byEmail.get(email);
    if (existing) return existing;
    const id = `user-${this.byEmail.size + 1}`;
    this.byEmail.set(email, id);
    this.byId.set(id, email);
    return id;
  }

  async findIdByEmail(email: string): Promise<string | null> {
    return this.byEmail.get(email) ?? null;
  }

  async findEmail(userId: string): Promise<string | null> {
    return this.byId.get(userId) ?? null;
  }

  async isAdmin(userId: string): Promise<boolean> {
    return this.adminId === userId;
  }
}

export class MemorySessionStore implements SessionStore {
  rows: SessionRow[] = [];

  async insert(session: SessionRecord): Promise<void> {
    this.rows.push({
      id: session.id,
      userId: session.userId,
      refreshTokenHash: session.refreshTokenHash,
      authMethod: session.authMethod,
      sourceAuthMethod: session.sourceAuthMethod,
      audiences: [...session.audiences],
      ip: session.ip,
      userAgent: session.userAgent,
      expiresAt: session.expiresAt,
      createdAt: new Date().toISOString(),
    });
  }

  async find(id: string): Promise<SessionRow | null> {
    return this.rows.find((row) => row.id === id) ?? null;
  }

  async rotate(id: string, expectedHash: string, nextHash: string, nextExpiresAt: string, now: string): Promise<boolean> {
    const row = this.rows.find((candidate) => candidate.id === id);
    if (!row || row.refreshTokenHash !== expectedHash || row.expiresAt <= now) return false;
    row.refreshTokenHash = nextHash;
    row.expiresAt = nextExpiresAt;
    return true;
  }

  async expire(id: string, now: string): Promise<void> {
    const row = this.rows.find((candidate) => candidate.id === id);
    if (row && row.expiresAt > now) row.expiresAt = now;
  }

  async listActive(userId: string, now: string): Promise<SessionRow[]> {
    return this.rows.filter((row) => row.userId === userId && row.expiresAt > now);
  }
}

export class MemoryKeyStore implements SigningKeyStore {
  rows: SigningKeyRow[] = [];

  async list(): Promise<SigningKeyRow[]> {
    return [...this.rows];
  }

  async insert(row: SigningKeyRow): Promise<void> {
    this.rows.push(row);
  }
}

export class MemoryCredentialStore {
  webauthn: Array<Record<string, unknown>> = [];
  ed25519: Array<Record<string, unknown>> = [];

  async listWebauthn(): Promise<Array<Record<string, unknown>>> {
    return this.webauthn;
  }

  async listEd25519(): Promise<Array<Record<string, unknown>>> {
    return this.ed25519;
  }
}
