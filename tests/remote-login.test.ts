import { describe, expect, it } from 'vitest';
import { ensureSigningKeys } from '../src/jwks';
import type { RemoteLoginDeps } from '../src/routes/remote-login';
import {
  handleRemoteLoginApprove,
  handleRemoteLoginClaim,
  handleRemoteLoginDeny,
  handleRemoteLoginExchange,
  handleRemoteLoginPending,
  handleRemoteLoginStart,
  handleSessionAuthorize,
} from '../src/routes/remote-login';
import { mintSession } from '../src/session';
import { MemoryCredentialStore, MemoryKeyStore, MemoryRemoteLoginStore, MemorySessionStore, MemoryUserStore } from './doubles';

const NOW = new Date('2026-10-26T08:00:00.000Z');
const ISSUER = 'https://auth.ntnl.io';

async function harness() {
  const keyStore = new MemoryKeyStore();
  await ensureSigningKeys(keyStore);
  const sessionStore = new MemorySessionStore();
  const userStore = new MemoryUserStore();
  const remoteLoginStore = new MemoryRemoteLoginStore();
  const deps: RemoteLoginDeps = {
    issuer: ISSUER,
    keyStore,
    sessionStore,
    userStore,
    credentialStore: new MemoryCredentialStore(),
    remoteLoginStore,
    clientIp: '203.0.113.11',
    userAgent: 'vitest',
    now: NOW,
  };
  const userId = await userStore.ensureByEmail('user@example.com', NOW.toISOString());
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
    isAdmin: false,
    now: NOW,
  });
  return { deps, keyStore, session, userId, sessionStore, userStore, remoteLoginStore };
}

function call(method: string, body?: unknown, token?: string): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token) headers['authorization'] = `Bearer ${token}`;
  return new Request('https://auth.ntnl.io/remote-login', {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

type Started = { request_id: string; exchange_code: string; confirmation_code: string; expires_at: string };

async function started(deps: RemoteLoginDeps, body: unknown = {}): Promise<Started> {
  const response = await handleRemoteLoginStart(call('POST', body), deps);
  expect(response.status).toBe(200);
  return (await response.json()) as Started;
}

describe('POST /remote-login/start', () => {
  it('issues a request id, a 64-hex exchange code and an 8-character human code', async () => {
    const { deps } = await harness();
    const body = await started(deps, { redirect_uri: 'https://linkit.ntnl.io/cb' });

    expect(body.request_id).toHaveLength(36);
    expect(body.exchange_code).toMatch(/^[0-9a-f]{64}$/);
    expect(body.confirmation_code).toMatch(/^[0-9A-F]{8}$/);
    expect(body.expires_at).toBe('2026-10-26T08:05:00.000Z');
    expect(JSON.stringify(body)).not.toContain('hash');
  });

  it('rejects malformed bodies and impossible audience combinations', async () => {
    const { deps } = await harness();
    expect((await handleRemoteLoginStart(call('POST', { extra: 1 }), deps)).status).toBe(400);
    expect((await handleRemoteLoginStart(call('POST', { aud: 'a.example', audiences: ['a.example'] }), deps)).status).toBe(400);
    expect((await handleRemoteLoginStart(call('POST', { redirect_uri: 'http://app.example.com/cb' }), deps)).status).toBe(400);
  });
});

describe('claim, approve and exchange', () => {
  it('walks the whole flow and mints an agent_approval session', async () => {
    const { deps, session, sessionStore } = await harness();
    const startedBody = await started(deps, { redirect_uri: 'https://linkit.ntnl.io/cb' });

    expect(((await (await handleRemoteLoginPending(call('GET', undefined, session.accessToken), deps)).json()) as { requests: unknown[] }).requests).toHaveLength(0);

    const claim = await handleRemoteLoginClaim(call('POST', { confirmation_code: startedBody.confirmation_code }, session.accessToken), deps);
    expect(claim.status).toBe(200);
    expect(await claim.json()).toMatchObject({ request_id: startedBody.request_id, audiences: ['linkit.ntnl.io'] });

    const pending = await handleRemoteLoginPending(call('GET', undefined, session.accessToken), deps);
    expect(((await pending.json()) as { requests: Array<Record<string, unknown>> }).requests[0]).toMatchObject({ request_id: startedBody.request_id });

    const approve = await handleRemoteLoginApprove(call('POST', undefined, session.accessToken), deps, startedBody.request_id);
    expect(await approve.json()).toEqual({ ok: true });

    const exchange = await handleRemoteLoginExchange(
      call('POST', { request_id: startedBody.request_id, exchange_code: startedBody.exchange_code }),
      deps,
      startedBody.request_id,
    );
    expect(exchange.status).toBe(200);
    const tokens = (await exchange.json()) as Record<string, string>;
    expect(tokens['token_type']).toBe('Bearer');

    const row = sessionStore.rows.at(-1)!;
    expect(row.authMethod).toBe('agent_approval');
    expect(row.audiences).toEqual(['linkit.ntnl.io']);

    const replay = await handleRemoteLoginExchange(
      call('POST', { request_id: startedBody.request_id, exchange_code: startedBody.exchange_code }),
      deps,
      startedBody.request_id,
    );
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({ error: 'remote_login_unavailable' });
  });

  it('refuses a wrong confirmation code, a denied request and an expired one', async () => {
    const { deps, session } = await harness();
    const startedBody = await started(deps);

    const wrong = await handleRemoteLoginClaim(call('POST', { confirmation_code: 'DEADBEEF' }, session.accessToken), deps);
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toEqual({ error: 'remote_login_unavailable' });

    await handleRemoteLoginClaim(call('POST', { confirmation_code: startedBody.confirmation_code }, session.accessToken), deps);
    expect(await (await handleRemoteLoginDeny(call('POST', undefined, session.accessToken), deps, startedBody.request_id)).json()).toEqual({ ok: true });

    const deniedExchange = await handleRemoteLoginExchange(
      call('POST', { request_id: startedBody.request_id, exchange_code: startedBody.exchange_code }),
      deps,
      startedBody.request_id,
    );
    expect(deniedExchange.status).toBe(401);

    const lateDeps: RemoteLoginDeps = { ...deps, now: new Date('2026-10-26T08:06:00.000Z') };
    const fresh = await started(deps);
    const lateClaim = await handleRemoteLoginClaim(call('POST', { confirmation_code: fresh.confirmation_code }, session.accessToken), lateDeps);
    expect(lateClaim.status).toBe(401);
  });

  it('requires the caller to own the request it decides on', async () => {
    const { deps, session, userStore, keyStore, sessionStore } = await harness();
    const otherId = await userStore.ensureByEmail('other@example.com', NOW.toISOString());
    const otherSession = await mintSession({
      keyStore,
      sessionStore,
      issuer: ISSUER,
      userId: otherId,
      authMethod: 'email_otp',
      sourceAuthMethod: null,
      audiences: ['auth.ntnl.io'],
      ip: null,
      userAgent: null,
      isAdmin: false,
      now: NOW,
    });

    const startedBody = await started(deps);
    await handleRemoteLoginClaim(call('POST', { confirmation_code: startedBody.confirmation_code }, session.accessToken), deps);

    const foreign = await handleRemoteLoginApprove(call('POST', undefined, otherSession.accessToken), deps, startedBody.request_id);
    expect(foreign.status).toBe(401);
    expect((await handleRemoteLoginPending(call('GET', undefined, otherSession.accessToken), deps)).status).toBe(200);
  });
});

describe('POST /session/authorize', () => {
  it('delegates to a downstream audience and records sso with its source', async () => {
    const { deps, session, sessionStore } = await harness();
    const response = await handleSessionAuthorize(
      call('POST', { redirect_uri: 'https://linkit.ntnl.io/cb' }, session.accessToken),
      deps,
    );
    expect(response.status).toBe(200);

    const row = sessionStore.rows.at(-1)!;
    expect(row.authMethod).toBe('sso');
    expect(row.sourceAuthMethod).toBe('email_otp');
    expect(row.audiences).toEqual(['linkit.ntnl.io']);
  });

  it('will not hand main-site tokens to a non-loopback target', async () => {
    const { deps, session } = await harness();
    const response = await handleSessionAuthorize(
      call('POST', { redirect_uri: 'https://auth.ntnl.io/cb', audiences: ['auth.ntnl.io'] }, session.accessToken),
      deps,
    );
    expect(response.status).toBe(400);
  });

  it('allows the issuer audience for a loopback target and requires a session', async () => {
    const { deps, session } = await harness();
    const loopback = await handleSessionAuthorize(
      call('POST', { redirect_uri: 'http://localhost:5173/cb', audiences: ['localhost'] }, session.accessToken),
      deps,
    );
    expect(loopback.status).toBe(200);

    expect((await handleSessionAuthorize(call('POST', { redirect_uri: 'https://linkit.ntnl.io/cb' }), deps)).status).toBe(401);
  });
});
