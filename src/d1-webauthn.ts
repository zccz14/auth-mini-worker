import type { StoredPasskeyRow, WebauthnChallenge, WebauthnChallengeType, WebauthnStore } from './stores';

interface ChallengeRow {
  request_id: string;
  type: WebauthnChallengeType;
  state_json: string;
  user_id: string | null;
  expires_at: string;
  rp_id: string;
  rp_name: string;
  origin: string;
  consumed_at: string | null;
}

const CHALLENGE_COLUMNS = 'request_id, type, state_json, user_id, expires_at, rp_id, rp_name, origin, consumed_at';

function toChallenge(row: ChallengeRow): WebauthnChallenge {
  return {
    requestId: row.request_id,
    type: row.type,
    stateJson: row.state_json,
    userId: row.user_id,
    expiresAt: row.expires_at,
    rpId: row.rp_id,
    rpName: row.rp_name,
    origin: row.origin,
    consumedAt: row.consumed_at,
  };
}

/** D1 statements report how many rows they touched; that is the only signal we get back. */
function changed(result: D1Result<unknown> | undefined): boolean {
  return (result?.meta?.changes ?? 0) > 0;
}

export class D1WebauthnStore implements WebauthnStore {
  constructor(private readonly db: D1Database) {}

  async expirePendingRegistrations(userId: string, now: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE webauthn_challenges SET consumed_at = ?1
         WHERE type = 'register' AND user_id = ?2 AND consumed_at IS NULL`,
      )
      .bind(now, userId)
      .run();
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
    await this.db
      .prepare(
        `INSERT INTO webauthn_challenges
         (request_id, type, state_json, user_id, expires_at, rp_id, rp_name, origin, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
      )
      .bind(
        challenge.requestId,
        challenge.type,
        challenge.stateJson,
        challenge.userId,
        challenge.expiresAt,
        challenge.rpId,
        challenge.rpName,
        challenge.origin,
        challenge.now,
      )
      .run();
  }

  async findChallenge(requestId: string, type: WebauthnChallengeType): Promise<WebauthnChallenge | null> {
    const row = await this.db
      .prepare(`SELECT ${CHALLENGE_COLUMNS} FROM webauthn_challenges WHERE request_id = ?1 AND type = ?2 LIMIT 1`)
      .bind(requestId, type)
      .first<ChallengeRow>();
    return row === null ? null : toChallenge(row);
  }

  async consumeChallenge(requestId: string, type: WebauthnChallengeType, now: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE webauthn_challenges SET consumed_at = ?1
         WHERE request_id = ?2 AND type = ?3 AND consumed_at IS NULL`,
      )
      .bind(now, requestId, type)
      .run();
    return changed(result);
  }

  async hasPasskey(userId: string): Promise<boolean> {
    const row = await this.db
      .prepare('SELECT 1 AS hit FROM webauthn_credentials WHERE user_id = ?1 LIMIT 1')
      .bind(userId)
      .first<{ hit: number }>();
    return row !== null;
  }

  async findCredential(credentialId: string, rpId: string): Promise<StoredPasskeyRow | null> {
    const row = await this.db
      .prepare('SELECT user_id, passkey_json FROM webauthn_credentials WHERE credential_id = ?1 AND rp_id = ?2 LIMIT 1')
      .bind(credentialId, rpId)
      .first<{ user_id: string; passkey_json: string }>();
    return row === null ? null : { userId: row.user_id, passkeyJson: row.passkey_json };
  }

  /**
   * `INSERT ... SELECT ... WHERE NOT EXISTS` is the guard for the Ed25519 path: the same statement
   * that writes the row also proves the user still has no passkey, so a second ceremony cannot slip
   * in between a check and the write.
   */
  async completeRegistration(input: {
    requestId: string;
    credentialId: string;
    userId: string;
    passkeyJson: string;
    rpId: string;
    firstOnly: boolean;
    now: string;
  }): Promise<{ consumed: boolean; stored: boolean }> {
    const insert = input.firstOnly
      ? this.db
          .prepare(
            `INSERT INTO webauthn_credentials (credential_id, user_id, passkey_json, rp_id)
             SELECT ?1, ?2, ?3, ?4
             WHERE NOT EXISTS (SELECT 1 FROM webauthn_credentials WHERE user_id = ?2)
             ON CONFLICT(credential_id) DO NOTHING`,
          )
          .bind(input.credentialId, input.userId, input.passkeyJson, input.rpId)
      : this.db
          .prepare(
            `INSERT INTO webauthn_credentials (credential_id, user_id, passkey_json, rp_id)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(credential_id) DO NOTHING`,
          )
          .bind(input.credentialId, input.userId, input.passkeyJson, input.rpId);

    const [consumedResult, insertResult] = await this.db.batch([
      this.db
        .prepare(
          `UPDATE webauthn_challenges SET consumed_at = ?1
           WHERE request_id = ?2 AND type = 'register' AND consumed_at IS NULL`,
        )
        .bind(input.now, input.requestId),
      insert,
    ]);

    return { consumed: changed(consumedResult), stored: changed(insertResult) };
  }

  async completeAuthentication(input: {
    requestId: string;
    credentialId: string;
    rpId: string;
    passkeyJson: string;
    now: string;
  }): Promise<{ consumed: boolean; updated: boolean }> {
    const [consumedResult, updateResult] = await this.db.batch([
      this.db
        .prepare(
          `UPDATE webauthn_challenges SET consumed_at = ?1
           WHERE request_id = ?2 AND type = 'authenticate' AND consumed_at IS NULL`,
        )
        .bind(input.now, input.requestId),
      this.db
        .prepare(
          `UPDATE webauthn_credentials SET passkey_json = ?1, last_used_at = ?2
           WHERE credential_id = ?3 AND rp_id = ?4`,
        )
        .bind(input.passkeyJson, input.now, input.credentialId, input.rpId),
    ]);

    return { consumed: changed(consumedResult), updated: changed(updateResult) };
  }

  async deleteCredential(credentialId: string, userId: string): Promise<boolean> {
    const result = await this.db
      .prepare('DELETE FROM webauthn_credentials WHERE credential_id = ?1 AND user_id = ?2')
      .bind(credentialId, userId)
      .run();
    return changed(result);
  }
}
