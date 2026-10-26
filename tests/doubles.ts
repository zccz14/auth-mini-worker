import type {
  Ed25519ChallengeRow,
  Ed25519CredentialRow,
  Ed25519Store,
  EmailOtpRecord,
  EmailOtpStore,
  SessionRecord,
  SessionRow,
  SessionStore,
  UserStore,
} from '../src/stores';
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

export class MemoryEd25519Store implements Ed25519Store {
  credentials: Ed25519CredentialRow[] = [];
  challenges: Ed25519ChallengeRow[] = [];
  private counter = 1;

  async credentialIdsByPublicKey(publicKey: string): Promise<string[]> {
    return this.credentials.filter((row) => row.publicKey === publicKey).map((row) => row.id);
  }

  async credentialById(id: string): Promise<Ed25519CredentialRow | null> {
    return this.credentials.find((row) => row.id === id) ?? null;
  }

  async listByUser(userId: string): Promise<Ed25519CredentialRow[]> {
    return this.credentials.filter((row) => row.userId === userId);
  }

  async create(userId: string, name: string, publicKey: string, now: string): Promise<Ed25519CredentialRow | null> {
    if (this.credentials.some((row) => row.publicKey === publicKey)) return null;
    const row: Ed25519CredentialRow = { id: `cred-${this.counter++}`, userId, name, publicKey, lastUsedAt: null, createdAt: now };
    this.credentials.push(row);
    return row;
  }

  async updateName(id: string, userId: string, name: string): Promise<Ed25519CredentialRow | null> {
    const row = this.credentials.find((candidate) => candidate.id === id);
    if (!row || row.userId !== userId) return null;
    row.name = name;
    return row;
  }

  async remove(id: string, userId: string): Promise<boolean> {
    const index = this.credentials.findIndex((candidate) => candidate.id === id && candidate.userId === userId);
    if (index < 0) return false;
    this.credentials.splice(index, 1);
    return true;
  }

  async createChallenge(requestId: string, credentialId: string, challenge: string, expiresAt: string, _now: string): Promise<void> {
    this.challenges.push({ requestId, credentialId, challenge, expiresAt, consumedAt: null });
  }

  async findChallenge(requestId: string): Promise<Ed25519ChallengeRow | null> {
    return this.challenges.find((row) => row.requestId === requestId) ?? null;
  }

  async consumeChallenge(requestId: string, now: string): Promise<boolean> {
    const row = this.challenges.find((candidate) => candidate.requestId === requestId);
    if (!row || row.consumedAt !== null || row.expiresAt <= now) return false;
    row.consumedAt = now;
    return true;
  }

  async touchLastUsed(credentialId: string, now: string): Promise<void> {
    const row = this.credentials.find((candidate) => candidate.id === credentialId);
    if (row) row.lastUsedAt = now;
  }
}
