import { describe, expect, it } from 'vitest';
import { base58Encode } from '../src/crypto/base58';
import { b64urlEncode } from '../src/crypto/b64url';
import { decodePublicKey, newChallenge, verifyChallengeSignature } from '../src/ed25519';
import { ensureSigningKeys } from '../src/jwks';
import type { Ed25519Deps } from '../src/routes/ed25519';
import {
  handleEd25519CredentialCreate,
  handleEd25519CredentialDelete,
  handleEd25519CredentialUpdate,
  handleEd25519CredentialsList,
  handleEd25519Start,
  handleEd25519Verify,
} from '../src/routes/ed25519';
import { mintSession } from '../src/session';
import { MemoryCredentialStore, MemoryEd25519Store, MemoryKeyStore, MemorySessionStore, MemoryUserStore } from './doubles';

const NOW = new Date('2026-10-26T07:00:00.000Z');
const ISSUER = 'https://auth.ntnl.io';
const ALG = { name: 'Ed25519' } as const;

async function deviceKey() {
  const pair = (await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const raw = new Uint8Array((await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer);
  return { pair, publicKey: base58Encode(raw) };
}

async function sign(pair: CryptoKeyPair, message: string): Promise<string> {
  return b64urlEncode(new Uint8Array(await crypto.subtle.sign(ALG, pair.privateKey, new TextEncoder().encode(message))));
}

async function harness() {
  const keyStore = new MemoryKeyStore();
  await ensureSigningKeys(keyStore);
  const sessionStore = new MemorySessionStore();
  const userStore = new MemoryUserStore();
  const ed25519Store = new MemoryEd25519Store();
  const deps: Ed25519Deps = {
    issuer: ISSUER,
    keyStore,
    sessionStore,
    userStore,
    credentialStore: new MemoryCredentialStore(),
    ed25519Store,
    clientIp: '203.0.113.9',
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
  return { deps, keyStore, sessionStore, userId, session, ed25519Store, userStore };
}

function call(method: string, body?: unknown, token?: string): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token) headers['authorization'] = `Bearer ${token}`;
  return new Request('https://auth.ntnl.io/ed25519', {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

describe('challenge verification', () => {
  it('accepts a real signature over the challenge bytes and nothing else', async () => {
    const { pair, publicKey } = await deviceKey();
    const challenge = newChallenge();

    expect(challenge).toMatch(/^[0-9a-f]{64}$/);
    expect(decodePublicKey(publicKey)).toHaveLength(32);
    expect(decodePublicKey('1'.repeat(32))).toHaveLength(32);
    expect(decodePublicKey('not base58!')).toBeNull();

    expect(await verifyChallengeSignature(challenge, publicKey, await sign(pair, challenge))).toBe(true);
    expect(await verifyChallengeSignature(`${challenge}x`, publicKey, await sign(pair, challenge))).toBe(false);
    expect(await verifyChallengeSignature(challenge, publicKey, 'short')).toBe(false);

    const other = await deviceKey();
    expect(await verifyChallengeSignature(challenge, publicKey, await sign(other.pair, challenge))).toBe(false);
  });
});

describe('POST /ed25519/start', () => {
  it('issues a challenge bound to the registered key', async () => {
    const { deps, userId, ed25519Store } = await harness();
    const { publicKey } = await deviceKey();
    await ed25519Store.create(userId, 'laptop', publicKey, NOW.toISOString());

    const response = await handleEd25519Start(call('POST', { public_key: publicKey }), deps);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, string>;
    expect(body['request_id']).toHaveLength(36);
    expect(body['challenge']).toMatch(/^[0-9a-f]{64}$/);

    const stored = await ed25519Store.findChallenge(body['request_id']!);
    expect(stored).toMatchObject({ challenge: body['challenge'], consumedAt: null, expiresAt: '2026-10-26T07:05:00.000Z' });
  });

  it('refuses an unknown key, a malformed key and extra fields', async () => {
    const { deps } = await harness();
    const { publicKey } = await deviceKey();

    expect((await handleEd25519Start(call('POST', { public_key: publicKey }), deps)).status).toBe(400);
    expect(await (await handleEd25519Start(call('POST', { public_key: publicKey }), deps)).json()).toEqual({
      error: 'invalid_ed25519_authentication',
    });
    expect((await handleEd25519Start(call('POST', { public_key: 'nope' }), deps)).status).toBe(400);
    expect((await handleEd25519Start(call('POST', { public_key: publicKey, extra: 1 }), deps)).status).toBe(400);
  });
});

describe('POST /ed25519/verify', () => {
  async function started() {
    const context = await harness();
    const { pair, publicKey } = await deviceKey();
    await context.ed25519Store.create(context.userId, 'laptop', publicKey, NOW.toISOString());
    const startResponse = await handleEd25519Start(call('POST', { public_key: publicKey }), context.deps);
    const { request_id: requestId, challenge } = (await startResponse.json()) as Record<string, string>;
    return { ...context, pair, publicKey, requestId: requestId!, challenge: challenge! };
  }

  it('mints an ed25519 session and marks the credential used', async () => {
    const { deps, pair, requestId, challenge, ed25519Store, sessionStore } = await started();
    const response = await handleEd25519Verify(call('POST', { request_id: requestId, signature: await sign(pair, challenge) }), deps);

    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, string>;
    expect(body['token_type']).toBe('Bearer');

    const row = sessionStore.rows.at(-1)!;
    expect(row.authMethod).toBe('ed25519');
    expect(row.audiences).toEqual(['auth.ntnl.io']);
    expect(ed25519Store.credentials[0]!.lastUsedAt).toBe(NOW.toISOString());
  });

  it('refuses replay, a wrong signature and an expired challenge', async () => {
    const { deps, pair, requestId, challenge } = await started();
    const signature = await sign(pair, challenge);

    expect((await handleEd25519Verify(call('POST', { request_id: requestId, signature }), deps)).status).toBe(200);
    const replay = await handleEd25519Verify(call('POST', { request_id: requestId, signature }), deps);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: 'invalid_ed25519_authentication' });

    const second = await started();
    expect((await handleEd25519Verify(call('POST', { request_id: second.requestId, signature: 'AAAA' }), second.deps)).status).toBe(400);

    const lateDeps: Ed25519Deps = { ...second.deps, now: new Date('2026-10-26T07:06:00.000Z') };
    const expired = await handleEd25519Verify(
      call('POST', { request_id: second.requestId, signature: await sign(second.pair, second.challenge) }),
      lateDeps,
    );
    expect(expired.status).toBe(400);
  });

  it('rejects malformed bodies with invalid_request', async () => {
    const { deps } = await harness();
    expect((await handleEd25519Verify(call('POST', { request_id: 'short', signature: 'x' }), deps)).status).toBe(400);
    expect((await handleEd25519Verify(call('POST', { request_id: '0'.repeat(36) }), deps)).status).toBe(400);
    expect((await handleEd25519Verify(call('POST', { request_id: '0'.repeat(36), signature: 'x', extra: 1 }), deps)).status).toBe(400);
  });
});

describe('credential management', () => {
  it('creates, lists, renames and deletes for a strong session', async () => {
    const { deps, session } = await harness();
    const { publicKey } = await deviceKey();

    const created = await handleEd25519CredentialCreate(call('POST', { name: 'laptop', public_key: publicKey }, session.accessToken), deps);
    expect(created.status).toBe(200);
    const credential = (await created.json()) as Record<string, string>;
    expect(credential).toMatchObject({ name: 'laptop', public_key: publicKey, last_used_at: null });

    const duplicate = await handleEd25519CredentialCreate(call('POST', { name: 'again', public_key: publicKey }, session.accessToken), deps);
    expect(duplicate.status).toBe(400);
    expect(await duplicate.json()).toEqual({ error: 'invalid_ed25519_credential' });

    const listed = await handleEd25519CredentialsList(call('GET', undefined, session.accessToken), deps);
    expect((await listed.json()) as unknown[]).toHaveLength(1);

    const renamed = await handleEd25519CredentialUpdate(call('PATCH', { name: 'renamed' }, session.accessToken), deps, credential['id']!);
    expect((await renamed.json()) as Record<string, unknown>).toMatchObject({ name: 'renamed' });

    const deleted = await handleEd25519CredentialDelete(call('DELETE', undefined, session.accessToken), deps, credential['id']!);
    expect(await deleted.json()).toEqual({ ok: true });

    const missing = await handleEd25519CredentialDelete(call('DELETE', undefined, session.accessToken), deps, credential['id']!);
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: 'credential_not_found' });
  });

  it('refuses management from an ed25519 session and from no session at all', async () => {
    const { deps, keyStore, sessionStore, userId } = await harness();
    const weak = await mintSession({
      keyStore,
      sessionStore,
      issuer: ISSUER,
      userId,
      authMethod: 'ed25519',
      sourceAuthMethod: null,
      audiences: ['auth.ntnl.io'],
      ip: null,
      userAgent: null,
      isAdmin: false,
      now: NOW,
    });

    const forbidden = await handleEd25519CredentialsList(call('GET', undefined, weak.accessToken), deps);
    expect(forbidden.status).toBe(403);
    expect(await forbidden.json()).toEqual({ error: 'insufficient_authentication_method' });

    expect((await handleEd25519CredentialsList(call('GET'), deps)).status).toBe(401);
  });
});
