/** Storage seams for the email OTP flow; D1 implementations live in d1-stores.ts. */

export interface EmailOtpRecord {
  codeHash: string;
  expiresAt: string;
  consumedAt: string | null;
}

export interface EmailOtpStore {
  /** Insert or replace the pending code for an address, clearing any previous consumption. */
  upsert(email: string, codeHash: string, expiresAt: string): Promise<void>;
  /** Mark the pending code unusable, used when delivery fails. */
  invalidate(email: string): Promise<void>;
  /** One conditional UPDATE: true only when this call consumed a live, matching code. */
  consume(email: string, codeHash: string, now: string): Promise<boolean>;
  find(email: string): Promise<EmailOtpRecord | null>;
}

export interface UserStore {
  /** Insert-or-ignore by email, then return the id, so an address never forks into two users. */
  ensureByEmail(email: string, now: string): Promise<string>;
  findIdByEmail(email: string): Promise<string | null>;
  findEmail(userId: string): Promise<string | null>;
  isAdmin(userId: string): Promise<boolean>;
}

export interface SessionRow {
  id: string;
  userId: string;
  refreshTokenHash: string;
  authMethod: string;
  sourceAuthMethod: string | null;
  audiences: string[];
  ip: string | null;
  userAgent: string | null;
  expiresAt: string;
  createdAt: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  refreshTokenHash: string;
  authMethod: string;
  sourceAuthMethod: string | null;
  audiences: readonly string[];
  ip: string | null;
  userAgent: string | null;
  expiresAt: string;
}

export interface SessionStore {
  insert(session: SessionRecord): Promise<void>;
  find(id: string): Promise<SessionRow | null>;
  /** Conditional rotation: true only when the stored hash still equals `expectedHash`. */
  rotate(id: string, expectedHash: string, nextHash: string, nextExpiresAt: string, now: string): Promise<boolean>;
  /** Legacy logout truncates the session by moving `expires_at` to now. */
  expire(id: string, now: string): Promise<void>;
  listActive(userId: string, now: string): Promise<SessionRow[]>;
}

export interface CredentialStore {
  listWebauthn(userId: string): Promise<Array<Record<string, unknown>>>;
  listEd25519(userId: string): Promise<Array<Record<string, unknown>>>;
}

export interface AppMetaStore {
  readIssuer(): Promise<string>;
}

export interface AppConfig {
  issuer: string;
  rpId: string;
  brandName: string;
  brandBackgroundImage: string;
  adminUserId: string | null;
}

export interface SmtpSummary {
  id: number;
  host: string;
  port: number;
  username: string;
  fromEmail: string;
  fromName: string;
  secure: boolean;
  isActive: boolean;
  weight: number;
}

export interface SmtpInput {
  id: number | null;
  host: string;
  port: number;
  username: string;
  password: string;
  fromEmail: string;
  fromName: string;
  secure: boolean;
  weight: number;
}

export interface AdminCredentialSummary {
  id: string;
  name: string;
  public_key: string;
  last_used_at: string | null;
  created_at: string;
}

export interface AdminStore {
  readConfig(): Promise<AppConfig>;
  writeConfig(config: Omit<AppConfig, 'adminUserId'>): Promise<void>;
  listSmtpSummaries(): Promise<SmtpSummary[]>;
  /** Full replace, exactly like `replace_smtp_configs`: ids not present are deleted. */
  replaceSmtp(inputs: readonly SmtpInput[]): Promise<void>;
  firstAdminCredential(): Promise<AdminCredentialSummary | null>;
  /** Creates the admin user (no email) if missing, then attaches the Ed25519 key. */
  installAdminEd25519(name: string, publicKey: string, now: string): Promise<void>;
}

export interface Ed25519CredentialRow {
  id: string;
  userId: string;
  name: string;
  publicKey: string;
  lastUsedAt: string | null;
  createdAt: string;
}

export interface Ed25519ChallengeRow {
  requestId: string;
  credentialId: string;
  challenge: string;
  expiresAt: string;
  consumedAt: string | null;
}

export interface Ed25519Store {
  credentialIdsByPublicKey(publicKey: string): Promise<string[]>;
  credentialById(id: string): Promise<Ed25519CredentialRow | null>;
  listByUser(userId: string): Promise<Ed25519CredentialRow[]>;
  /** Returns null when this public key is already registered. */
  create(userId: string, name: string, publicKey: string, now: string): Promise<Ed25519CredentialRow | null>;
  updateName(id: string, userId: string, name: string): Promise<Ed25519CredentialRow | null>;
  remove(id: string, userId: string): Promise<boolean>;
  createChallenge(requestId: string, credentialId: string, challenge: string, expiresAt: string, now: string): Promise<void>;
  findChallenge(requestId: string): Promise<Ed25519ChallengeRow | null>;
  /** One conditional UPDATE: true only when this call consumed a live challenge. */
  consumeChallenge(requestId: string, now: string): Promise<boolean>;
  touchLastUsed(credentialId: string, now: string): Promise<void>;
}
