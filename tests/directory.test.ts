import { describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/crypto/tokens';
import { ensureSigningKeys } from '../src/jwks';
import type { DirectoryDeps } from '../src/routes/directory';
import { handleAdminUsers, handleIntegrationUserIds, handleUserDirectoryToken } from '../src/routes/directory';
import { mintSession } from '../src/session';
import {
  MemoryAdminStore,
  MemoryCredentialStore,
  MemoryDirectoryStore,
  MemoryKeyStore,
  MemoryMailTemplateStore,
  MemoryRequestStatsStore,
  MemorySessionStore,
  MemoryUserStore,
  MemoryWebauthnStore,
} from './doubles';

const NOW = new Date('2026-10-26T09:00:00.000Z');
const ISSUER = 'https://auth.ntnl.io';

async function harness(options: { admin?: boolean } = {}) {
  const keyStore = new MemoryKeyStore();
  await ensureSigningKeys(keyStore);
  const sessionStore = new MemorySessionStore();
  const userStore = new MemoryUserStore();
  const directoryStore = new MemoryDirectoryStore();

  const userId = await userStore.ensureByEmail('admin@example.com', NOW.toISOString());
  if (options.admin ?? true) userStore.adminId = userId;

  const deps: DirectoryDeps = {
    issuer: ISSUER,
    keyStore,
    sessionStore,
    userStore,
    credentialStore: new MemoryCredentialStore(),
    adminStore: new MemoryAdminStore(),
    webauthnStore: new MemoryWebauthnStore(),
    requestStatsStore: new MemoryRequestStatsStore(),
    mailTemplates: new MemoryMailTemplateStore(),
    setupToken: null,
    directoryStore,
    now: NOW,
  };

  const session = await mintSession({
    keyStore,
    sessionStore,
    issuer: ISSUER,
    userId,
    authMethod: 'email_otp',
    sourceAuthMethod: null,
    audiences: ['auth.ntnl.io'],
    ip: null,
    userAgent: null,
    isAdmin: options.admin ?? true,
    now: NOW,
  });

  return { deps, session, directoryStore, userStore };
}

function call(method: string, token?: string, bearer?: string): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token) headers['authorization'] = `Bearer ${token}`;
  if (bearer) headers['authorization'] = `Bearer ${bearer}`;
  return new Request('https://auth.ntnl.io/', { method, headers });
}

describe('directory token administration', () => {
  it('reports unconfigured, rotates once into an am_uid_ token, and never stores it in the clear', async () => {
    const { deps, session, directoryStore } = await harness();

    const before = await handleUserDirectoryToken(call('GET', session.accessToken), deps);
    expect(await before.json()).toEqual({ configured: false, created_at: null });
    expect(before.headers.get('cache-control')).toBe('no-store');

    const rotated = await handleUserDirectoryToken(call('POST', session.accessToken), deps);
    expect(rotated.status).toBe(201);
    const { token } = (await rotated.json()) as { token: string };

    expect(token).toMatch(/^am_uid_[0-9a-f]{64}$/);
    expect(token).toHaveLength(71);
    expect(directoryStore.tokenHash).toBe(await sha256Hex(token));
    expect(directoryStore.tokenHash).not.toContain(token);

    const after = await handleUserDirectoryToken(call('GET', session.accessToken), deps);
    expect(await after.json()).toEqual({ configured: true, created_at: '2026-10-26T09:00:00.000Z' });
  });

  it('requires an admin token and refuses unauthenticated callers', async () => {
    const { deps } = await harness({ admin: false });
    expect((await handleUserDirectoryToken(call('GET'), deps)).status).toBe(401);
    expect((await handleUserDirectoryToken(call('POST'), deps)).status).toBe(401);
  });

  it('refuses a signed-in user who is not the admin', async () => {
    const { deps, session } = await harness({ admin: false });
    const response = await handleUserDirectoryToken(call('POST', session.accessToken), deps);
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: 'admin_required' });
  });

  it('revokes by deleting the row', async () => {
    const { deps, session, directoryStore } = await harness();
    const { token } = (await (await handleUserDirectoryToken(call('POST', session.accessToken), deps)).json()) as { token: string };
    directoryStore.ids = ['a'];

    expect((await handleIntegrationUserIds(call('GET', undefined, token), deps)).status).toBe(200);

    const removed = await handleUserDirectoryToken(call('DELETE', session.accessToken), deps);
    expect(removed.status).toBe(204);
    expect((await handleIntegrationUserIds(call('GET', undefined, token), deps)).status).toBe(401);
  });
});

describe('GET /integration/user-ids', () => {
  it('returns every id without CORS headers, and refuses anything but a live directory token', async () => {
    const { deps, session, directoryStore } = await harness();
    directoryStore.ids = ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'];

    const { token } = (await (await handleUserDirectoryToken(call('POST', session.accessToken), deps)).json()) as { token: string };

    const ok = await handleIntegrationUserIds(call('GET', undefined, token), deps);
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ user_ids: directoryStore.ids });
    expect(ok.headers.get('access-control-allow-origin')).toBeNull();
    expect(ok.headers.get('cache-control')).toBe('no-store');

    for (const bad of ['', 'am_uid_short', `am_uid_${'0'.repeat(64)}`, session.accessToken]) {
      const response = await handleIntegrationUserIds(bad === '' ? call('GET') : call('GET', undefined, bad), deps);
      expect(response.status, bad.slice(0, 12)).toBe(401);
      expect(await response.json()).toEqual({ error: 'invalid_directory_token' });
    }
  });

  it('rotating invalidates the previous token immediately', async () => {
    const { deps, session } = await harness();
    const first = (await (await handleUserDirectoryToken(call('POST', session.accessToken), deps)).json()) as { token: string };
    const second = (await (await handleUserDirectoryToken(call('POST', session.accessToken), deps)).json()) as { token: string };

    expect(first.token).not.toBe(second.token);
    expect((await handleIntegrationUserIds(call('GET', undefined, first.token), deps)).status).toBe(401);
    expect((await handleIntegrationUserIds(call('GET', undefined, second.token), deps)).status).toBe(200);
  });
});

describe('GET /admin/users', () => {
  it('returns the counts the admin UI shows', async () => {
    const { deps, session, directoryStore } = await harness();
    directoryStore.users = [
      {
        id: 'user-1',
        email: 'user@example.com',
        emailVerifiedAt: '2026-10-26T09:00:00.000Z',
        createdAt: '2026-10-20T09:00:00.000Z',
        activeSessionCount: 2,
        passkeyCount: 1,
        ed25519Count: 3,
      },
    ];

    const response = await handleAdminUsers(call('GET', session.accessToken), deps);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      users: [
        {
          id: 'user-1',
          email: 'user@example.com',
          email_verified_at: '2026-10-26T09:00:00.000Z',
          created_at: '2026-10-20T09:00:00.000Z',
          active_session_count: 2,
          passkey_count: 1,
          ed25519_count: 3,
        },
      ],
    });
  });
});
