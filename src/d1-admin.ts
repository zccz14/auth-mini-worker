import { uuidv4 } from './crypto/tokens';
import type { AdminCredentialSummary, AdminStore, AppConfig, SmtpInput, SmtpSummary } from './stores';

interface AppMetaRow {
  issuer: string;
  rp_id: string;
  brand_name: string;
  brand_background_image: string;
  admin_user_id: string | null;
}

export class D1AdminStore implements AdminStore {
  constructor(private readonly db: D1Database) {}

  private async ensureAppRow(): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO app_meta (id, issuer, rp_id, brand_name, brand_background_image)
         VALUES ('APP', 'http://localhost:7777', 'localhost', 'auth-mini', '')`,
      )
      .run();
  }

  async readConfig(): Promise<AppConfig> {
    await this.ensureAppRow();
    const row = await this.db
      .prepare("SELECT issuer, rp_id, brand_name, brand_background_image, admin_user_id FROM app_meta WHERE id = 'APP'")
      .first<AppMetaRow>();
    if (!row) throw new Error('app_meta_missing');
    return {
      issuer: row.issuer,
      rpId: row.rp_id,
      brandName: row.brand_name,
      brandBackgroundImage: row.brand_background_image,
      adminUserId: row.admin_user_id,
    };
  }

  async writeConfig(config: Omit<AppConfig, 'adminUserId'>): Promise<void> {
    await this.ensureAppRow();
    await this.db
      .prepare(
        `UPDATE app_meta SET issuer = ?1, rp_id = ?2, brand_name = ?3, brand_background_image = ?4,
                             updated_at = CURRENT_TIMESTAMP
         WHERE id = 'APP'`,
      )
      .bind(config.issuer, config.rpId, config.brandName, config.brandBackgroundImage)
      .run();
  }

  async listSmtpSummaries(): Promise<SmtpSummary[]> {
    const { results } = await this.db
      .prepare(
        `SELECT id, host, port, username, from_email, from_name, secure, is_active, weight
         FROM smtp_configs ORDER BY id ASC`,
      )
      .all<{
        id: number;
        host: string;
        port: number;
        username: string;
        from_email: string;
        from_name: string;
        secure: number;
        is_active: number;
        weight: number;
      }>();
    return results.map((row) => ({
      id: row.id,
      host: row.host,
      port: row.port,
      username: row.username,
      fromEmail: row.from_email,
      fromName: row.from_name,
      secure: row.secure === 1,
      isActive: row.is_active === 1,
      weight: row.weight,
    }));
  }

  async replaceSmtp(inputs: readonly SmtpInput[]): Promise<void> {
    const { results } = await this.db.prepare('SELECT id FROM smtp_configs').all<{ id: number }>();
    const existing = new Set(results.map((row) => row.id));
    const retained = new Set<number>();

    for (const input of inputs) {
      if (input.id === null) {
        await this.db
          .prepare(
            `INSERT INTO smtp_configs (host, port, username, password, from_email, from_name, secure, weight)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
          )
          .bind(input.host, input.port, input.username, input.password, input.fromEmail, input.fromName, input.secure ? 1 : 0, input.weight)
          .run();
        continue;
      }
      if (!existing.has(input.id) || retained.has(input.id)) throw new Error('invalid_smtp_id');
      retained.add(input.id);
      // An empty password means "keep the stored one", so editing a row never needs the secret.
      await this.db
        .prepare(
          `UPDATE smtp_configs SET host = ?1, port = ?2, username = ?3,
                                   password = COALESCE(NULLIF(?4, ''), password),
                                   from_email = ?5, from_name = ?6, secure = ?7, weight = ?8
           WHERE id = ?9`,
        )
        .bind(input.host, input.port, input.username, input.password, input.fromEmail, input.fromName, input.secure ? 1 : 0, input.weight, input.id)
        .run();
    }

    for (const id of existing) {
      if (retained.has(id)) continue;
      await this.db.prepare('DELETE FROM smtp_configs WHERE id = ?1').bind(id).run();
    }
  }

  async firstAdminCredential(): Promise<AdminCredentialSummary | null> {
    const row = await this.db
      .prepare(
        `SELECT c.id, c.name, c.public_key, c.last_used_at, c.created_at
         FROM ed25519_credentials c JOIN app_meta m ON m.admin_user_id = c.user_id
         WHERE m.id = 'APP' ORDER BY c.created_at ASC, c.id ASC LIMIT 1`,
      )
      .first<AdminCredentialSummary>();
    return row ?? null;
  }

  async ensureRootUser(): Promise<string> {
    await this.ensureAppRow();
    // An unclaimed instance has at most one "root user without a credential" — the leftover of an
    // abandoned attempt. Reusing it keeps `users` clean; the `admin_user_id` exclusion matters
    // because the claimed root user itself never has an email.
    const pending = await this.db
      .prepare(
        `SELECT u.id FROM users u
          WHERE u.email IS NULL
            AND u.id <> COALESCE((SELECT admin_user_id FROM app_meta WHERE id = 'APP'), '')
            AND NOT EXISTS (SELECT 1 FROM webauthn_credentials c WHERE c.user_id = u.id)
            AND NOT EXISTS (SELECT 1 FROM ed25519_credentials e WHERE e.user_id = u.id)
          ORDER BY u.created_at ASC, u.id ASC
          LIMIT 1`,
      )
      .first<{ id: string }>();
    if (pending !== null) return pending.id;

    const id = uuidv4();
    await this.db.prepare('INSERT INTO users (id, email) VALUES (?1, NULL)').bind(id).run();
    return id;
  }

  async claimRootUser(userId: string, relyingParty: { issuer: string; rpId: string }): Promise<boolean> {
    await this.ensureAppRow();
    const result = await this.db
      .prepare(
        `UPDATE app_meta SET admin_user_id = ?1, issuer = ?2, rp_id = ?3, updated_at = CURRENT_TIMESTAMP
         WHERE id = 'APP' AND admin_user_id IS NULL`,
      )
      .bind(userId, relyingParty.issuer, relyingParty.rpId)
      .run();
    return (result.meta?.changes ?? 0) > 0;
  }
}
