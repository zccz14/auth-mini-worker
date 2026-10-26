import type {
  Ed25519ChallengeRow,
  Ed25519CredentialRow,
  Ed25519Store,
  EmailOtpRecord,
  EmailOtpStore,
  RemoteLoginRow,
  RemoteLoginStore,
  SessionRecord,
  SessionRow,
  SessionStore,
  UserStore,
  UserSummary,
  DirectoryStore,
  AdminCredentialSummary,
  AdminStore,
  AppConfig,
  SmtpInput,
  SmtpSummary,
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

  async rotate(next: SigningKeyRow): Promise<void> {
    const standby = this.rows.find((row) => row.slot === 'STANDBY');
    if (!standby) throw new Error('missing_standby_key');
    this.rows = this.rows.filter((row) => row.slot !== 'CURRENT');
    standby.slot = 'CURRENT';
    this.rows.push(next);
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

export class MemoryRemoteLoginStore implements RemoteLoginStore {
  rows: Array<RemoteLoginRow & { exchangeCodeHash: string; confirmationCodeHash: string }> = [];

  async create(row: {
    requestId: string;
    exchangeCodeHash: string;
    confirmationCodeHash: string;
    redirectUri: string | null;
    audiences: readonly string[];
    expiresAt: string;
    now: string;
  }): Promise<void> {
    this.rows.push({
      requestId: row.requestId,
      redirectUri: row.redirectUri,
      audiences: [...row.audiences],
      expiresAt: row.expiresAt,
      createdAt: row.now,
      status: 'pending',
      approvedUserId: null,
      exchangeCodeHash: row.exchangeCodeHash,
      confirmationCodeHash: row.confirmationCodeHash,
    });
  }

  async findIdByConfirmationCode(confirmationCodeHash: string, now: string): Promise<string | null> {
    return this.rows.find((row) => row.confirmationCodeHash === confirmationCodeHash && row.status === 'pending' && row.approvedUserId === null && row.expiresAt > now)?.requestId ?? null;
  }

  async claim(requestId: string, userId: string, confirmationCodeHash: string, now: string): Promise<boolean> {
    const row = this.rows.find((candidate) => candidate.requestId === requestId);
    if (!row || row.confirmationCodeHash !== confirmationCodeHash || row.status !== 'pending' || row.approvedUserId !== null || row.expiresAt <= now) return false;
    row.approvedUserId = userId;
    return true;
  }

  async expireStale(now: string): Promise<void> {
    for (const row of this.rows) if (row.status === 'pending' && row.expiresAt <= now) row.status = 'expired';
  }

  async listPending(userId: string, now: string): Promise<RemoteLoginRow[]> {
    return this.rows.filter((row) => row.approvedUserId === userId && row.status === 'pending' && row.expiresAt > now);
  }

  async summary(requestId: string, userId: string): Promise<RemoteLoginRow | null> {
    return this.rows.find((row) => row.requestId === requestId && row.approvedUserId === userId && row.status === 'pending') ?? null;
  }

  async decide(requestId: string, userId: string, status: 'approved' | 'denied', now: string): Promise<boolean> {
    const row = this.rows.find((candidate) => candidate.requestId === requestId);
    if (!row || row.approvedUserId !== userId || row.status !== 'pending' || row.expiresAt <= now) return false;
    row.status = status;
    return true;
  }

  async findApproved(requestId: string, exchangeCodeHash: string, now: string): Promise<{ userId: string; audiences: string[] } | null> {
    const row = this.rows.find((candidate) => candidate.requestId === requestId && candidate.exchangeCodeHash === exchangeCodeHash && candidate.status === 'approved' && candidate.expiresAt > now);
    if (!row?.approvedUserId) return null;
    return { userId: row.approvedUserId, audiences: row.audiences };
  }

  async consume(requestId: string, exchangeCodeHash: string, now: string): Promise<boolean> {
    const row = this.rows.find((candidate) => candidate.requestId === requestId);
    if (!row || row.exchangeCodeHash !== exchangeCodeHash || row.status !== 'approved' || row.expiresAt <= now) return false;
    row.status = 'consumed';
    return true;
  }
}

export class MemoryDirectoryStore implements DirectoryStore {
  tokenHash: string | null = null;
  createdAt: string | null = null;
  ids: string[] = [];
  users: UserSummary[] = [];

  async tokenStatus(): Promise<{ configured: boolean; createdAt: string | null }> {
    return { configured: this.tokenHash !== null, createdAt: this.createdAt };
  }

  async rotateToken(tokenHash: string): Promise<string> {
    this.tokenHash = tokenHash;
    this.createdAt = '2026-10-26T09:00:00.000Z';
    return this.createdAt;
  }

  async clearToken(): Promise<void> {
    this.tokenHash = null;
    this.createdAt = null;
  }

  async matchesTokenHash(tokenHash: string): Promise<boolean> {
    return this.tokenHash !== null && this.tokenHash === tokenHash;
  }

  async listUserIds(): Promise<string[]> {
    return [...this.ids];
  }

  async listUsers(): Promise<UserSummary[]> {
    return this.users;
  }
}

export class MemoryAdminStore implements AdminStore {
  config: AppConfig = {
    issuer: 'https://auth.ntnl.io',
    rpId: 'auth.ntnl.io',
    brandName: 'auth-mini',
    brandBackgroundImage: '',
    adminUserId: 'admin-user',
  };
  smtp: Array<SmtpSummary & { password: string }> = [];
  adminCredential: AdminCredentialSummary | null = null;
  private nextId = 1;

  async readConfig(): Promise<AppConfig> {
    return { ...this.config };
  }

  async writeConfig(config: Omit<AppConfig, 'adminUserId'>): Promise<void> {
    this.config = { ...this.config, ...config };
  }

  async listSmtpSummaries(): Promise<SmtpSummary[]> {
    return this.smtp.map(({ password: _password, ...summary }) => summary);
  }

  async replaceSmtp(inputs: readonly SmtpInput[]): Promise<void> {
    const existing = new Set(this.smtp.map((row) => row.id));
    const retained = new Set<number>();
    for (const input of inputs) {
      if (input.id === null) {
        this.smtp.push({ ...input, id: this.nextId++, isActive: true });
        continue;
      }
      if (!existing.has(input.id) || retained.has(input.id)) throw new Error('invalid_smtp_id');
      retained.add(input.id);
      const row = this.smtp.find((candidate) => candidate.id === input.id)!;
      Object.assign(row, { ...input, password: input.password === '' ? row.password : input.password });
    }
    this.smtp = this.smtp.filter((row) => retained.has(row.id) || !existing.has(row.id));
  }

  async firstAdminCredential(): Promise<AdminCredentialSummary | null> {
    return this.adminCredential;
  }

  async installAdminEd25519(name: string, publicKey: string, now: string): Promise<void> {
    this.config.adminUserId = this.config.adminUserId ?? 'admin-user';
    this.adminCredential = { id: 'cred-1', name, public_key: publicKey, last_used_at: null, created_at: now };
  }
}
