import { describe, expect, it } from 'vitest';
import { normalizeAllowedOrigin, normalizeRpId, validateRpIdForIssuer, AdminValidationError } from '../src/admin/validate';
import { ensureSigningKeys } from '../src/jwks';
import type { AdminDeps } from '../src/routes/admin';
import { handleAdminConfig, handleAdminSetup } from '../src/routes/admin';
import { mintSession } from '../src/session';
import type { AdminCredentialSummary, AdminStore, AppConfig, SmtpInput, SmtpSummary } from '../src/stores';
import { MemoryCredentialStore, MemoryKeyStore, MemorySessionStore, MemoryUserStore } from './doubles';

const NOW = new Date('2026-10-26T06:00:00.000Z');
const ISSUER = 'https://auth.ntnl.io';
const VALID_KEY = '1'.repeat(32);

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

describe('GET/PUT /admin/setup', () => {
  it('reports the uninitialised state and installs the admin key once', async () => {
    const { deps, adminStore } = await harness();
    const before = await handleAdminSetup(request('GET'), deps);
    expect(before.status).toBe(200);
    expect(await before.json()).toMatchObject({ admin_user_id: null, admin_ed25519: null, smtp: null });

    const installed = await handleAdminSetup(request('PUT', { admin_ed25519: { name: 'ops laptop', public_key: VALID_KEY } }), deps);
    expect(installed.status).toBe(200);
    const state = (await installed.json()) as Record<string, unknown>;
    expect(state['admin_user_id']).toBe('admin-user');
    expect(state['admin_ed25519']).toMatchObject({ name: 'ops laptop', public_key: VALID_KEY });
    expect(adminStore.adminCredential?.created_at).toBe(NOW.toISOString());

    const second = await handleAdminSetup(request('PUT', { admin_ed25519: { name: 'again', public_key: VALID_KEY } }), deps);
    expect(second.status).toBe(409);
    expect(await second.json()).toEqual({ error: 'already_initialized' });
    expect((await handleAdminSetup(request('GET'), deps)).status).toBe(403);
  });

  it('rejects keys that are not 32 base58 bytes and bodies with extra fields', async () => {
    const { deps } = await harness();
    expect((await handleAdminSetup(request('PUT', { admin_ed25519: { name: 'x', public_key: 'not base58!' } }), deps)).status).toBe(400);
    expect((await handleAdminSetup(request('PUT', { admin_ed25519: { name: 'x', public_key: 'abc' } }), deps)).status).toBe(400);
    expect((await handleAdminSetup(request('PUT', { admin_ed25519: { name: 'x', public_key: VALID_KEY, extra: 1 } }), deps)).status).toBe(400);
    expect((await handleAdminSetup(request('PUT', { admin_ed25519: { name: '  ', public_key: VALID_KEY } }), deps)).status).toBe(400);
  });

  it('honours the setup token when one is configured', async () => {
    const { deps } = await harness({ setupToken: 'shhh' });
    expect((await handleAdminSetup(request('PUT', { admin_ed25519: { name: 'x', public_key: VALID_KEY } }), deps)).status).toBe(403);

    const allowed = await handleAdminSetup(
      request('PUT', { admin_ed25519: { name: 'x', public_key: VALID_KEY } }, undefined, { 'x-admin-setup-token': 'shhh' }),
      deps,
    );
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
});
