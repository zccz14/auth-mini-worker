import type {
  Ed25519ChallengeRow,
  Ed25519CredentialRow,
  Ed25519Store,
  EmailChangeOtpStore,
  EmailOtpRecord,
  EndpointTotals,
  ProbeTotals,
  RequestHit,
  RequestProbe,
  RequestStatsStore,
  EmailOtpStore,
  RemoteLoginRow,
  RemoteLoginStore,
  SessionRecord,
  SessionRow,
  SessionStore,
  UserStore,
  UserSummary,
  DirectoryStore,
  WebauthnChallenge,
  WebauthnChallengeType,
  WebauthnStore,
  AdminCredentialSummary,
  AdminStore,
  AppConfig,
  SmtpInput,
  SmtpSummary,
} from '../src/stores';
import {
  EMPTY_MAIL_TEMPLATES,
  type MailTemplateConfig,
  type MailTemplateOverrides,
  type MailTemplateStore,
} from '../src/mail/template';
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

export class MemoryEmailChangeStore implements EmailChangeOtpStore {
  /** Pending code per user, exactly like the `user_id` primary key. */
  rows = new Map<string, { email: string; codeHash: string; expiresAt: string; consumedAt: string | null }>();
  /** Addresses owned by some account; `assignEmail` refuses them and moves the owner's row. */
  taken = new Set<string>();
  assigned = new Map<string, { email: string; at: string }>();

  async emailInUse(email: string): Promise<boolean> {
    return this.taken.has(email);
  }

  async upsert(userId: string, email: string, codeHash: string, expiresAt: string): Promise<void> {
    this.rows.set(userId, { email, codeHash, expiresAt, consumedAt: null });
  }

  async invalidate(userId: string): Promise<void> {
    const row = this.rows.get(userId);
    if (row) row.consumedAt = new Date().toISOString();
  }

  async consume(userId: string, email: string, codeHash: string, now: string): Promise<boolean> {
    const row = this.rows.get(userId);
    if (!row || row.consumedAt !== null || row.expiresAt <= now || row.codeHash !== codeHash || row.email !== email) {
      return false;
    }
    row.consumedAt = now;
    return true;
  }

  async assignEmail(userId: string, email: string, now: string): Promise<boolean> {
    if (this.taken.has(email)) return false;
    this.taken.add(email);
    this.assigned.set(userId, { email, at: now });
    return true;
  }
}

export class MemoryRequestStatsStore implements RequestStatsStore {
  hits: RequestHit[] = [];
  probes: RequestProbe[] = [];
  prunedBefore: number[] = [];

  async recordHit(hit: RequestHit): Promise<void> {
    this.hits.push({ ...hit });
  }

  async recordProbe(probe: RequestProbe): Promise<void> {
    this.probes.push({ ...probe });
  }

  async summarize(
    sinceBucket: number,
    options: { endpointLimit: number; probeLimit: number },
  ): Promise<{
    endpoints: EndpointTotals[];
    probes: ProbeTotals[];
    probeOverflow: { count: number; lastSeen: number } | null;
  }> {
    const endpoints = new Map<string, EndpointTotals>();
    for (const hit of this.hits) {
      if (hit.bucket < sinceBucket) continue;
      const key = `${hit.method} ${hit.endpoint}`;
      const row = endpoints.get(key) ?? { method: hit.method, endpoint: hit.endpoint, count: 0, errorCount: 0, totalMs: 0 };
      row.count += hit.hits;
      row.totalMs += hit.totalMs;
      if (hit.status >= 400) row.errorCount += hit.hits;
      endpoints.set(key, row);
    }

    const probes = new Map<string, ProbeTotals>();
    for (const probe of this.probes) {
      if (probe.bucket < sinceBucket) continue;
      const key = `${probe.method} ${probe.path}`;
      const row = probes.get(key) ?? { method: probe.method, path: probe.path, count: 0, lastSeen: 0 };
      row.count += probe.hits;
      row.lastSeen = Math.max(row.lastSeen, probe.now);
      probes.set(key, row);
    }

    const rankedProbes = [...probes.values()].sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));
    const totalProbeHits = rankedProbes.reduce((sum, row) => sum + row.count, 0);
    const listedProbes = rankedProbes.slice(0, options.probeLimit);
    const listedHits = listedProbes.reduce((sum, row) => sum + row.count, 0);

    return {
      endpoints: [...endpoints.values()]
        .sort((a, b) => b.count - a.count || a.endpoint.localeCompare(b.endpoint))
        .slice(0, options.endpointLimit),
      probes: listedProbes,
      probeOverflow:
        totalProbeHits > listedHits
          ? { count: totalProbeHits - listedHits, lastSeen: Math.max(...rankedProbes.map((row) => row.lastSeen)) }
          : null,
    };
  }

  async prune(beforeBucket: number): Promise<void> {
    this.prunedBefore.push(beforeBucket);
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

export class MemoryWebauthnStore implements WebauthnStore {
  challenges = new Map<string, WebauthnChallenge>();
  credentials: Array<{
    credentialId: string;
    userId: string;
    passkeyJson: string;
    rpId: string;
    lastUsedAt: string | null;
  }> = [];

  async expirePendingRegistrations(userId: string, now: string): Promise<void> {
    for (const challenge of this.challenges.values()) {
      if (challenge.type === 'register' && challenge.userId === userId && challenge.consumedAt === null) {
        challenge.consumedAt = now;
      }
    }
  }

  async insertChallenge(challenge: {
    requestId: string;
    type: WebauthnChallengeType;
    stateJson: string;
    userId: string | null;
    expiresAt: string;
    rpId: string;
    rpName: string;
    origin: string;
    now: string;
  }): Promise<void> {
    this.challenges.set(challenge.requestId, {
      requestId: challenge.requestId,
      type: challenge.type,
      stateJson: challenge.stateJson,
      userId: challenge.userId,
      expiresAt: challenge.expiresAt,
      rpId: challenge.rpId,
      rpName: challenge.rpName,
      origin: challenge.origin,
      consumedAt: null,
    });
  }

  async findChallenge(requestId: string, type: WebauthnChallengeType): Promise<WebauthnChallenge | null> {
    const row = this.challenges.get(requestId);
    return row && row.type === type ? { ...row } : null;
  }

  async consumeChallenge(requestId: string, type: WebauthnChallengeType, now: string): Promise<boolean> {
    const row = this.challenges.get(requestId);
    if (!row || row.type !== type || row.consumedAt !== null) return false;
    row.consumedAt = now;
    return true;
  }

  async hasPasskey(userId: string): Promise<boolean> {
    return this.credentials.some((row) => row.userId === userId);
  }

  async findCredential(credentialId: string, rpId: string): Promise<{ userId: string; passkeyJson: string } | null> {
    const row = this.credentials.find((entry) => entry.credentialId === credentialId && entry.rpId === rpId);
    return row ? { userId: row.userId, passkeyJson: row.passkeyJson } : null;
  }

  /** Mirrors the D1 batch: both statements run, so a tripped guard still spends the challenge. */
  async completeRegistration(input: {
    requestId: string;
    credentialId: string;
    userId: string;
    passkeyJson: string;
    rpId: string;
    firstOnly: boolean;
    now: string;
  }): Promise<{ consumed: boolean; stored: boolean }> {
    const consumed = await this.consumeChallenge(input.requestId, 'register', input.now);
    const blocked = input.firstOnly && (await this.hasPasskey(input.userId));
    if (blocked) return { consumed, stored: false };
    if (this.credentials.some((entry) => entry.credentialId === input.credentialId)) {
      return { consumed, stored: false };
    }
    this.credentials.push({
      credentialId: input.credentialId,
      userId: input.userId,
      passkeyJson: input.passkeyJson,
      rpId: input.rpId,
      lastUsedAt: null,
    });
    return { consumed, stored: true };
  }

  async completeAuthentication(input: {
    requestId: string;
    credentialId: string;
    rpId: string;
    passkeyJson: string;
    now: string;
  }): Promise<{ consumed: boolean; updated: boolean }> {
    const consumed = await this.consumeChallenge(input.requestId, 'authenticate', input.now);
    const row = this.credentials.find(
      (entry) => entry.credentialId === input.credentialId && entry.rpId === input.rpId,
    );
    if (!row) return { consumed, updated: false };
    row.passkeyJson = input.passkeyJson;
    row.lastUsedAt = input.now;
    return { consumed, updated: true };
  }

  async deleteCredential(credentialId: string, userId: string): Promise<boolean> {
    const index = this.credentials.findIndex(
      (entry) => entry.credentialId === credentialId && entry.userId === userId,
    );
    if (index < 0) return false;
    this.credentials.splice(index, 1);
    return true;
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
  pendingRootUser: string | null = null;
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

  async ensureRootUser(): Promise<string> {
    this.pendingRootUser = this.pendingRootUser ?? `root-${++this.nextId}`;
    return this.pendingRootUser;
  }

  async claimRootUser(userId: string, relyingParty: { issuer: string; rpId: string }): Promise<boolean> {
    if (this.config.adminUserId !== null) return false;
    this.config = { ...this.config, adminUserId: userId, issuer: relyingParty.issuer, rpId: relyingParty.rpId };
    return true;
  }
}

/**
 * Templates live beside the brand (`app_meta` holds both), so the double keeps them together too:
 * `brandName` mirrors `MemoryAdminStore.config.brandName` unless a test renames this instance.
 */
export class MemoryMailTemplateStore implements MailTemplateStore {
  brandName = 'auth-mini';
  overrides: MailTemplateOverrides = { ...EMPTY_MAIL_TEMPLATES };

  async read(): Promise<MailTemplateConfig> {
    return { brandName: this.brandName, overrides: { ...this.overrides } };
  }

  async write(overrides: MailTemplateOverrides): Promise<void> {
    this.overrides = { ...overrides };
  }
}
