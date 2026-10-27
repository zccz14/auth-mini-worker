import { describe, expect, it } from 'vitest';
import { normalizeAllowedOrigin, normalizeRpId, validateRpIdForIssuer, AdminValidationError } from '../src/admin/validate';
import { ensureSigningKeys } from '../src/jwks';
import type { AdminDeps } from '../src/routes/admin';
import { handleAdminConfig, handleAdminSetup } from '../src/routes/admin';
import { mintSession } from '../src/session';
import type { AdminCredentialSummary, AdminStore, AppConfig, SmtpInput, SmtpSummary } from '../src/stores';
import { MemoryCredentialStore, MemoryKeyStore, MemorySessionStore, MemoryUserStore, MemoryWebauthnStore } from './doubles';

const NOW = new Date('2026-10-26T06:00:00.000Z');
const ISSUER = 'https://auth.ntnl.io';

class MemoryAdminStore implements AdminStore {
  config: AppConfig = {
    issuer: 'http://localhost:7777',
    rpId: 'localhost',
    brandName: 'auth-mini',
    brandBackgroundImage: '',
    adminUserId: null,
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
    this.pendingRootUser = this.pendingRootUser ?? 'root-user';
    return this.pendingRootUser;
  }

  async claimRootUser(userId: string, relyingParty: { issuer: string; rpId: string }): Promise<boolean> {
    if (this.config.adminUserId !== null) return false;
    this.config = { ...this.config, adminUserId: userId, issuer: relyingParty.issuer, rpId: relyingParty.rpId };
    return true;
  }
}

async function harness(options: { admin?: boolean; setupToken?: string | null } = {}) {
  const keyStore = new MemoryKeyStore();
  await ensureSigningKeys(keyStore);
  const sessionStore = new MemorySessionStore();
  const userStore = new MemoryUserStore();
  const adminStore = new MemoryAdminStore();
  const userId = await userStore.ensureByEmail('admin@example.com', NOW.toISOString());
  if (options.admin) userStore.adminId = userId;

  const deps: AdminDeps = {
    issuer: ISSUER,
    keyStore,
    sessionStore,
    userStore,
    credentialStore: new MemoryCredentialStore(),
    now: NOW,
    adminStore,
    webauthnStore: new MemoryWebauthnStore(),
    setupToken: options.setupToken ?? null,
  };

  const pair = await mintSession({
    keyStore,
    sessionStore,
    issuer: ISSUER,
    userId,
    authMethod: 'email_otp',
    sourceAuthMethod: null,
    audiences: ['auth.ntnl.io'],
    ip: null,
    userAgent: null,
    isAdmin: options.admin ?? false,
    now: NOW,
  });
  return { deps, pair, adminStore, userStore };
}

function request(method: string, body?: unknown, token?: string, headers: Record<string, string> = {}): Request {
  const all: Record<string, string> = { 'content-type': 'application/json', ...headers };
  if (token) all['authorization'] = `Bearer ${token}`;
  return new Request('https://auth.ntnl.io/admin', {
    method,
    headers: all,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

describe('admin validation', () => {
  it('normalises issuer origins and rejects anything but scheme://host[:port]', () => {
    expect(normalizeAllowedOrigin(' https://auth.ntnl.io/ ')).toBe('https://auth.ntnl.io');
    expect(normalizeAllowedOrigin('http://localhost:7777')).toBe('http://localhost:7777');
    for (const bad of ['ftp://auth.ntnl.io', 'https://auth.ntnl.io/admin', 'https://auth.ntnl.io/?x=1', 'https://user:pw@auth.ntnl.io', 'auth.ntnl.io']) {
      expect(() => normalizeAllowedOrigin(bad), bad).toThrow(AdminValidationError);
    }
  });

  it('accepts only plain DNS labels as rp_id', () => {
    expect(normalizeRpId(' Auth.NTNL.io. ')).toBe('auth.ntnl.io');
    for (const bad of ['', 'localhost:7777', 'auth/ntnl', 'a..b', 'a_b.example', 'user@example.com']) {
      expect(() => normalizeRpId(bad), bad).toThrow(AdminValidationError);
    }
  });

  it('binds rp_id to the issuer host', () => {
    expect(() => validateRpIdForIssuer('https://auth.ntnl.io', 'auth.ntnl.io')).not.toThrow();
    expect(() => validateRpIdForIssuer('https://auth.ntnl.io', 'ntnl.io')).not.toThrow();
    expect(() => validateRpIdForIssuer('https://auth.ntnl.io', 'linkit.ntnl.io')).toThrow(AdminValidationError);
    expect(() => validateRpIdForIssuer('http://localhost:7777', 'localhost')).not.toThrow();
    expect(() => validateRpIdForIssuer('https://1.2.3.4', '2.3.4')).toThrow(AdminValidationError);
  });
});

describe('GET /admin/setup', () => {
  it('answers with the first-run projection only', async () => {
    const { deps } = await harness();
    const response = await handleAdminSetup(request('GET'), deps);
    expect(response.status).toBe(200);

    // An anonymous caller learns whether the instance still needs its root user and what the
    // unauthenticated shell renders. The administrator's credentials and the SMTP fleet are
    // `/admin/config`, behind a token.
    expect(await response.json()).toEqual({
      admin_user_id: null,
      issuer: 'http://localhost:7777',
      rp_id: 'localhost',
      brand_name: 'auth-mini',
      brand_background_image: '',
    });
  });

  it('refuses once the root user is claimed', async () => {
    const { deps, adminStore } = await harness();
    await adminStore.claimRootUser('root-user', { issuer: ISSUER, rpId: 'auth.ntnl.io' });

    const response = await handleAdminSetup(request('GET'), deps);
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: 'admin_setup_forbidden' });
  });

  it('separates a missing setup token from an already-claimed instance', async () => {
    const { deps } = await harness({ setupToken: 'shhh' });

    // A wrong token is not "already initialized": the GUI has to be able to tell the owner to
    // paste the token instead of hiding the first-run page forever.
    const denied = await handleAdminSetup(request('GET'), deps);
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: 'admin_setup_token_required' });

    const allowed = await handleAdminSetup(request('GET', undefined, undefined, { 'x-admin-setup-token': 'shhh' }), deps);
    expect(allowed.status).toBe(200);
  });
});

describe('GET/PUT /admin/config', () => {
  it('requires a token and the admin flag', async () => {
    const { deps, pair: userPair } = await harness({ admin: false });
    expect((await handleAdminConfig(request('GET'), deps)).status).toBe(401);
    expect((await handleAdminConfig(request('GET', undefined, userPair.accessToken), deps)).status).toBe(403);
  });

  it('writes issuer, rp_id and branding for an admin', async () => {
    const { deps, adminStore, pair } = await harness({ admin: true });
    const response = await handleAdminConfig(
      request('PUT', { issuer: 'https://auth.ntnl.io', rp_id: 'auth.ntnl.io', brand_name: 'NTNL', brand_background_image: '' }, pair.accessToken),
      deps,
    );

    expect(response.status).toBe(200);
    expect(adminStore.config).toMatchObject({ issuer: 'https://auth.ntnl.io', rpId: 'auth.ntnl.io', brandName: 'NTNL' });
    expect((await response.json()) as Record<string, unknown>).toMatchObject({ issuer: 'https://auth.ntnl.io', rp_id: 'auth.ntnl.io' });
  });

  it('rejects an rp_id that does not belong to the issuer', async () => {
    const { deps, pair } = await harness({ admin: true });
    const response = await handleAdminConfig(
      request('PUT', { issuer: 'https://auth.ntnl.io', rp_id: 'other.example', brand_name: 'NTNL', brand_background_image: '' }, pair.accessToken),
      deps,
    );
    expect(response.status).toBe(400);
  });

  it('replaces the SMTP rows and never echoes a password', async () => {
    const { deps, adminStore, pair } = await harness({ admin: true });
    const created = await handleAdminConfig(
      request(
        'PUT',
        {
          issuer: 'https://auth.ntnl.io',
          rp_id: 'auth.ntnl.io',
          brand_name: 'NTNL',
          brand_background_image: '',
          smtp: [{ host: 'smtp.feishu.cn', port: 587, username: 'auth@ntnl.io', password: 'secret', from_email: 'auth@ntnl.io', from_name: 'NTNL', secure: true, weight: 1 }],
        },
        pair.accessToken,
      ),
      deps,
    );
    expect(created.status).toBe(200);
    const body = (await created.json()) as Record<string, unknown>;
    expect(JSON.stringify(body)).not.toContain('secret');
    expect(adminStore.smtp).toHaveLength(1);

    // The wire shape is AdminSmtpConfigSummary: snake_case, no password, is_active present.
    expect((body['smtp'] as Array<Record<string, unknown>>)[0]).toEqual({
      id: 1,
      host: 'smtp.feishu.cn',
      port: 587,
      username: 'auth@ntnl.io',
      from_email: 'auth@ntnl.io',
      from_name: 'NTNL',
      secure: true,
      is_active: true,
      weight: 1,
    });

    const edited = await handleAdminConfig(
      request(
        'PUT',
        {
          issuer: 'https://auth.ntnl.io',
          rp_id: 'auth.ntnl.io',
          brand_name: 'NTNL',
          brand_background_image: '',
          smtp: [{ id: 1, host: 'smtp.feishu.cn', port: 465, username: 'auth@ntnl.io', password: '', from_email: 'auth@ntnl.io', from_name: 'NTNL', secure: true, weight: 2 }],
        },
        pair.accessToken,
      ),
      deps,
    );
    expect(edited.status).toBe(200);
    expect(adminStore.smtp[0]).toMatchObject({ id: 1, port: 465, weight: 2, password: 'secret' });
  });

  it('refuses a new SMTP row without a password and an unknown id', async () => {
    const { deps, pair } = await harness({ admin: true });
    const base = { issuer: 'https://auth.ntnl.io', rp_id: 'auth.ntnl.io', brand_name: 'NTNL', brand_background_image: '' };

    const noPassword = await handleAdminConfig(
      request('PUT', { ...base, smtp: [{ host: 'smtp.example.com', port: 587, username: 'u', password: '', from_email: 'a@b.c', from_name: '', secure: true, weight: 1 }] }, pair.accessToken),
      deps,
    );
    expect(noPassword.status).toBe(400);

    const unknownId = await handleAdminConfig(
      request('PUT', { ...base, smtp: [{ id: 99, host: 'smtp.example.com', port: 587, username: 'u', password: 'x', from_email: 'a@b.c', from_name: '', secure: true, weight: 1 }] }, pair.accessToken),
      deps,
    );
    expect(unknownId.status).toBe(400);
  });

  it('tells browsers not to cache authorization state', async () => {
    const { deps } = await harness({ admin: false });
    const state = await handleAdminSetup(request('GET'), deps);
    expect(state.status).toBe(200);
    expect(state.headers.get('cache-control')).toBe('no-store');
  });
});
