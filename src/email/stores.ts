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
  isAdmin(userId: string): Promise<boolean>;
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
}

export interface AppMetaStore {
  readIssuer(): Promise<string>;
}
