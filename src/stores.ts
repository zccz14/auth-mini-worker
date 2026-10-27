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

/** The pending email change of an authenticated user; one row per user, replaced on retry. */
export interface EmailChangeOtpStore {
  /** True when any account already owns the address. */
  emailInUse(email: string): Promise<boolean>;
  upsert(userId: string, email: string, codeHash: string, expiresAt: string): Promise<void>;
  /** Marks the pending code unusable, used when delivery fails. */
  invalidate(userId: string): Promise<void>;
  /** One conditional UPDATE: true only when this call spent a live, matching code. */
  consume(userId: string, email: string, codeHash: string, now: string): Promise<boolean>;
  /** True when the address was free and this user now owns it; also stamps `email_verified_at`. */
  assignEmail(userId: string, email: string, now: string): Promise<boolean>;
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
  /**
   * Returns the not-yet-claimed root user, creating one when the instance has none.
   *
   * A registration challenge holds a foreign key to `users` and cannot be anonymous, so the row
   * has to exist before the ceremony starts — the claim itself only happens once the credential
   * has been verified. Reusing an abandoned attempt keeps ghost accounts out of the directory.
   */
  ensureRootUser(): Promise<string>;
  /**
   * Points `app_meta.admin_user_id` at the root user and records the origin its passkeys belong
   * to. False when somebody else claimed the instance first; the caller must not report success,
   * because a second administrator cannot be created this way and the loser's credential is inert.
   */
  claimRootUser(userId: string, relyingParty: { issuer: string; rpId: string }): Promise<boolean>;
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

export interface RemoteLoginRow {
  requestId: string;
  redirectUri: string | null;
  audiences: string[];
  expiresAt: string;
  createdAt: string;
  status: string;
  approvedUserId: string | null;
}

export interface RemoteLoginStore {
  create(row: {
    requestId: string;
    exchangeCodeHash: string;
    confirmationCodeHash: string;
    redirectUri: string | null;
    audiences: readonly string[];
    expiresAt: string;
    now: string;
  }): Promise<void>;
  /** Binds a pending request to the user who is approving it; false when nothing matched. */
  claim(requestId: string, userId: string, confirmationCodeHash: string, now: string): Promise<boolean>;
  findIdByConfirmationCode(confirmationCodeHash: string, now: string): Promise<string | null>;
  expireStale(now: string): Promise<void>;
  listPending(userId: string, now: string): Promise<RemoteLoginRow[]>;
  summary(requestId: string, userId: string): Promise<RemoteLoginRow | null>;
  /** pending -> approved/denied, only for the user the request is bound to. */
  decide(requestId: string, userId: string, status: 'approved' | 'denied', now: string): Promise<boolean>;
  /** Reads the approved request without consuming it. */
  findApproved(requestId: string, exchangeCodeHash: string, now: string): Promise<{ userId: string; audiences: string[] } | null>;
  /** approved -> consumed, one conditional UPDATE. */
  consume(requestId: string, exchangeCodeHash: string, now: string): Promise<boolean>;
}

export interface UserSummary {
  id: string;
  email: string | null;
  emailVerifiedAt: string | null;
  createdAt: string;
  activeSessionCount: number;
  passkeyCount: number;
  ed25519Count: number;
}

export interface DirectoryStore {
  tokenStatus(): Promise<{ configured: boolean; createdAt: string | null }>;
  /** Writes a new hash, returns the new creation timestamp; the plaintext never comes back. */
  rotateToken(tokenHash: string): Promise<string>;
  clearToken(): Promise<void>;
  matchesTokenHash(tokenHash: string): Promise<boolean>;
  listUserIds(): Promise<string[]>;
  listUsers(now: string): Promise<UserSummary[]>;
}

export type WebauthnChallengeType = 'register' | 'authenticate';

export interface WebauthnChallenge {
  requestId: string;
  type: WebauthnChallengeType;
  stateJson: string;
  userId: string | null;
  expiresAt: string;
  rpId: string;
  rpName: string;
  origin: string;
  consumedAt: string | null;
}

export interface StoredPasskeyRow {
  userId: string;
  passkeyJson: string;
}

export interface WebauthnStore {
  /** Kills the caller's unused registration challenges; the legacy handler does this per options call. */
  expirePendingRegistrations(userId: string, now: string): Promise<void>;
  insertChallenge(challenge: {
    requestId: string;
    type: WebauthnChallengeType;
    stateJson: string;
    userId: string | null;
    expiresAt: string;
    rpId: string;
    rpName: string;
    origin: string;
    now: string;
  }): Promise<void>;
  findChallenge(requestId: string, type: WebauthnChallengeType): Promise<WebauthnChallenge | null>;
  /** One conditional UPDATE: true only when this call spent a live, unconsumed challenge. */
  consumeChallenge(requestId: string, type: WebauthnChallengeType, now: string): Promise<boolean>;
  hasPasskey(userId: string): Promise<boolean>;
  findCredential(credentialId: string, rpId: string): Promise<StoredPasskeyRow | null>;
  /**
   * Spend the registration challenge and store the credential in one batch. With `firstOnly` the
   * insert additionally requires that the user still has no passkey, which is how an Ed25519
   * session is held to "first passkey only" even if another ceremony landed in between.
   */
  completeRegistration(input: {
    requestId: string;
    credentialId: string;
    userId: string;
    passkeyJson: string;
    rpId: string;
    firstOnly: boolean;
    now: string;
  }): Promise<{ consumed: boolean; stored: boolean }>;
  /** Spend the assertion challenge and move the counter, in one batch. */
  completeAuthentication(input: {
    requestId: string;
    credentialId: string;
    rpId: string;
    passkeyJson: string;
    now: string;
  }): Promise<{ consumed: boolean; updated: boolean }>;
  deleteCredential(credentialId: string, userId: string): Promise<boolean>;
}
