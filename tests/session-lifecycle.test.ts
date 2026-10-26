import { describe, expect, it } from 'vitest';
import { authenticateAccessToken } from '../src/auth';
import { sha256Hex } from '../src/crypto/tokens';
import { ensureSigningKeys } from '../src/jwks';
import { verifyAccessToken } from '../src/jwt';
import type { SessionDeps } from '../src/routes/session';
import { handleMe, handleSessionLogout, handleSessionRefresh, handleTime } from '../src/routes/session';
import { mintSession } from '../src/session';
import { MemoryCredentialStore, MemoryKeyStore, MemorySessionStore, MemoryUserStore } from './doubles';

const NOW = new Date('2026-10-26T05:00:00.000Z');
const LATER = new Date('2026-10-26T05:05:00.000Z');
const ISSUER = 'https://auth.ntnl.io';

async function harness() {
  const keyStore = new MemoryKeyStore();
  await ensureSigningKeys(keyStore);
  const sessionStore = new MemorySessionStore();
  const userStore = new MemoryUserStore();
  const credentialStore = new MemoryCredentialStore();
  const deps: SessionDeps = { issuer: ISSUER, keyStore, sessionStore, userStore, credentialStore, now: NOW };

  const userId = await userStore.ensureByEmail('user@example.com', NOW.toISOString());
  const pair = await mintSession({
    keyStore,
    sessionStore,
    issuer: ISSUER,
    userId,
    authMethod: 'email_otp',
    sourceAuthMethod: null,
    audiences: ['auth.ntnl.io'],
    ip: '203.0.113.7',
    userAgent: 'vitest',
    isAdmin: false,
    now: NOW,
  });
  return { deps, keyStore, sessionStore, userStore, credentialStore, userId, pair };
}

function post(body: unknown, token?: string): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token) headers['authorization'] = `Bearer ${token}`;
  return new Request('https://auth.ntnl.io/', { method: 'POST', headers, body: JSON.stringify(body) });
}

function get(token?: string): Request {
  const headers: Record<string, string> = {};
  if (token) headers['authorization'] = `Bearer ${token}`;
  return new Request('https://auth.ntnl.io/me', { headers });
}

describe('POST /session/refresh', () => {
  it('rotates the refresh token and mints a token that still verifies', async () => {
    const { deps, pair, sessionStore, keyStore } = await harness();
    const response = await handleSessionRefresh(post({ session_id: pair.sessionId, refresh_token: pair.refreshToken }), deps);

    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, string>;
    expect(body['session_id']).toBe(pair.sessionId);
    expect(body['refresh_token']).not.toBe(pair.refreshToken);
    expect(body['expires_in']).toBe(900);

    const row = sessionStore.rows[0]!;
    expect(row.refreshTokenHash).toBe(await sha256Hex(body['refresh_token']!));
    expect(row.expiresAt > NOW.toISOString()).toBe(true);

    const key = await verifyAccessToken(
      { kid: [...keyStore.rows].find((r) => r.slot === 'CURRENT')!.kid, publicJwk: JSON.parse([...keyStore.rows][0]!.publicJwk) },
      body['access_token']!,
      Math.floor(NOW.getTime() / 1000),
    );
    expect(key).not.toBeNull();
  });

  it('answers session_superseded when the presented token was already rotated', async () => {
    const { deps, pair } = await harness();
    const first = await handleSessionRefresh(post({ session_id: pair.sessionId, refresh_token: pair.refreshToken }), deps);
    expect(first.status).toBe(200);

    const replay = await handleSessionRefresh(post({ session_id: pair.sessionId, refresh_token: pair.refreshToken }), deps);
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({ error: 'session_superseded' });
  });

  it('answers session_invalidated for unknown or expired sessions', async () => {
    const { deps, pair } = await harness();
    const unknown = await handleSessionRefresh(post({ session_id: '00000000-0000-4000-8000-000000000000', refresh_token: 'x' }), deps);
    expect(await unknown.json()).toEqual({ error: 'session_invalidated' });

    const expiredDeps: SessionDeps = { ...deps, now: new Date('2027-01-01T00:00:00.000Z') };
    const expired = await handleSessionRefresh(post({ session_id: pair.sessionId, refresh_token: pair.refreshToken }), expiredDeps);
    expect(await expired.json()).toEqual({ error: 'session_invalidated' });
  });

  it('rejects malformed bodies with invalid_request', async () => {
    const { deps, pair } = await harness();
    expect((await handleSessionRefresh(post({ session_id: pair.sessionId }), deps)).status).toBe(400);
    expect((await handleSessionRefresh(post({ session_id: 'short', refresh_token: 'x' }), deps)).status).toBe(400);
    expect((await handleSessionRefresh(post({ session_id: pair.sessionId, refresh_token: 'x', extra: 1 }), deps)).status).toBe(400);
  });
});

describe('access token authentication', () => {
  it('accepts the minted token and rejects a token whose session was expired', async () => {
    const { deps, pair } = await harness();
    const auth = await authenticateAccessToken(get(pair.accessToken), deps);
    expect(auth?.sessionId).toBe(pair.sessionId);

    const logout = await handleSessionLogout(post({}, pair.accessToken), deps);
    expect(logout.status).toBe(200);
    expect(await logout.json()).toEqual({ ok: true });

    // same signature, but the session row is now expired
    expect(await authenticateAccessToken(get(pair.accessToken), deps)).toBeNull();
  });

  it('rejects a token when the session audiences no longer agree', async () => {
    const { deps, pair, sessionStore } = await harness();
    sessionStore.rows[0]!.audiences = ['other.example'];

    expect(await authenticateAccessToken(get(pair.accessToken), deps)).toBeNull();
  });

  it('rejects a missing, malformed or foreign-issuer token', async () => {
    const { deps, pair } = await harness();
    expect(await authenticateAccessToken(get(), deps)).toBeNull();
    expect(await authenticateAccessToken(get('not-a-jwt'), deps)).toBeNull();
    expect(await authenticateAccessToken(get(pair.accessToken), { ...deps, issuer: 'https://elsewhere.example' })).toBeNull();
  });
});

describe('GET /me', () => {
  it('returns the profile with active sessions and credential lists', async () => {
    const { deps, pair, userId, credentialStore } = await harness();
    credentialStore.webauthn = [{ id: 'cred-1', credential_id: 'cred-1', transports: [], rp_id: 'auth.ntnl.io', last_used_at: null, created_at: NOW.toISOString() }];

    const response = await handleMe(get(pair.accessToken), deps);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;

    expect(Object.keys(body).sort()).toEqual([
      'active_sessions',
      'auth_admin',
      'ed25519_credentials',
      'email',
      'user_id',
      'webauthn_credentials',
    ]);
    expect(body['user_id']).toBe(userId);
    expect(body['email']).toBe('user@example.com');
    expect(body['auth_admin']).toBe(false);
    expect(body['webauthn_credentials']).toEqual(credentialStore.webauthn);
    expect((body['active_sessions'] as Array<Record<string, unknown>>)[0]).toMatchObject({
      id: pair.sessionId,
      auth_method: 'email_otp',
      aud: '["auth.ntnl.io"]',
      ip: '203.0.113.7',
    });
  });

  it('refuses a delegated audience and an unauthenticated call', async () => {
    const { deps, keyStore, sessionStore, userStore } = await harness();
    const userId = await userStore.ensureByEmail('delegated@example.com', NOW.toISOString());
    const delegated = await mintSession({
      keyStore,
      sessionStore,
      issuer: ISSUER,
      userId,
      authMethod: 'sso',
      sourceAuthMethod: 'email_otp',
      audiences: ['linkit.ntnl.io'],
      ip: null,
      userAgent: null,
      isAdmin: false,
      now: NOW,
    });

    expect((await handleMe(get(delegated.accessToken), deps)).status).toBe(401);
    expect((await handleMe(get(), deps)).status).toBe(401);
  });
});

describe('GET /time', () => {
  it('returns second, millisecond and ISO forms with no-store', () => {
    const response = handleTime(LATER);
    expect(response.headers.get('cache-control')).toBe('no-store');
    return response.json().then((body) => {
      expect(body).toEqual({
        now: Math.floor(LATER.getTime() / 1000),
        now_ms: LATER.getTime(),
        iso: LATER.toISOString(),
      });
    });
  });
});
