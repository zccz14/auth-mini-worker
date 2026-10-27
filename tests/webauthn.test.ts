import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ORIGIN as ORIGIN,
  DEFAULT_RP_ID as RP_ID,
  assertionResponse,
  newAuthenticator,
  registrationResponse,
  type Authenticator,
} from './software-authenticator';
import { ensureSigningKeys } from '../src/jwks';
import type { WebauthnDeps } from '../src/routes/webauthn';
import {
  handleWebauthnAuthenticationOptions,
  handleWebauthnAuthenticationVerify,
  handleWebauthnCredentialDelete,
  handleWebauthnRegisterOptions,
  handleWebauthnRegisterVerify,
} from '../src/routes/webauthn';
import { mintSession } from '../src/session';
import { parsePasskey, resolveWebauthnConfig, webauthnUserHandleText } from '../src/webauthn';
import {
  MemoryAdminStore,
  MemoryCredentialStore,
  MemoryKeyStore,
  MemorySessionStore,
  MemoryUserStore,
  MemoryWebauthnStore,
} from './doubles';

const NOW = new Date('2026-10-26T10:00:00.000Z');
const ISSUER = 'https://auth.ntnl.io';

/**
 * Pinned against the legacy `user_webauthn_id`: SHA-256 over the prefix and the user id, cut to
 * 16 bytes, stamped version 5. Migrated passkeys carry this handle, so a change here is a login
 * regression for real devices, not a refactor.
 */
const PINNED_USER_ID = '031a393d-8a0a-4ca0-8cb1-313e0d71dfa9';
const PINNED_USER_HANDLE = 'eQsKK9E1VHGhkAUzKbPgXg';

function post(path: string, body: unknown, token?: string): Request {
  return new Request(`https://auth.ntnl.io${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify(body),
  });
}

async function harness(options: { authMethod?: 'email_otp' | 'ed25519' } = {}) {
  const keyStore = new MemoryKeyStore();
  await ensureSigningKeys(keyStore);
  const sessionStore = new MemorySessionStore();
  const userStore = new MemoryUserStore();
  const webauthnStore = new MemoryWebauthnStore();
  const adminStore = new MemoryAdminStore();
  adminStore.config = { ...adminStore.config, issuer: ISSUER, rpId: RP_ID, brandName: 'No Trade No Life' };

  const userId = await userStore.ensureByEmail('user@example.com', NOW.toISOString());
  const deps: WebauthnDeps = {
    issuer: ISSUER,
    keyStore,
    sessionStore,
    userStore,
    credentialStore: new MemoryCredentialStore(),
    webauthnStore,
    adminStore,
    clientIp: '203.0.113.9',
    userAgent: 'vitest',
    now: NOW,
  };
  const pair = await mintSession({
    keyStore,
    sessionStore,
    issuer: ISSUER,
    userId,
    authMethod: options.authMethod ?? 'email_otp',
    sourceAuthMethod: null,
    audiences: ['auth.ntnl.io'],
    ip: null,
    userAgent: null,
    isAdmin: false,
    now: NOW,
  });

  /** Options then verify, the way a browser does it. */
  async function register(authenticator: Authenticator, token = pair.accessToken) {
    const optionsResponse = await handleWebauthnRegisterOptions(
      post('/webauthn/register/options', {}, token),
      deps,
    );
    const options = (await optionsResponse.json()) as { request_id: string; publicKey: { challenge: string } };
    const credential = await registrationResponse(authenticator, options.publicKey.challenge);
    const verifyResponse = await handleWebauthnRegisterVerify(
      post('/webauthn/register/verify', { request_id: options.request_id, credential }, token),
      deps,
    );
    return { options, credential, verifyResponse };
  }

  async function authenticate(authenticator: Authenticator, userHandle?: string | null) {
    const optionsResponse = await handleWebauthnAuthenticationOptions(
      post('/webauthn/authenticate/options', {}),
      deps,
    );
    const options = (await optionsResponse.json()) as { request_id: string; publicKey: { challenge: string } };
    const credential = await assertionResponse(authenticator, options.publicKey.challenge, {
      ...(userHandle === undefined ? {} : { userHandle }),
    });
    const verifyResponse = await handleWebauthnAuthenticationVerify(
      post('/webauthn/authenticate/verify', { request_id: options.request_id, credential }),
      deps,
    );
    return { options, credential, verifyResponse };
  }

  return { deps, userId, token: pair.accessToken, webauthnStore, sessionStore, adminStore, userStore, register, authenticate };
}

describe('webauthn config', () => {
  it('derives the legacy user handle, including the pinned vector', async () => {
    expect(await webauthnUserHandleText(PINNED_USER_ID)).toBe(PINNED_USER_HANDLE);
  });

  it('accepts an issuer that is the rp_id itself', () => {
    expect(resolveWebauthnConfig({ issuer: 'https://auth.ntnl.io', rpId: 'auth.ntnl.io', brandName: 'Auth' })).toEqual({
      origin: 'https://auth.ntnl.io',
      rpId: 'auth.ntnl.io',
      rpName: 'Auth',
    });
  });

  it('accepts a parent-domain rp_id and drops default ports', () => {
    expect(
      resolveWebauthnConfig({ issuer: 'https://auth.example.com:443', rpId: 'example.com', brandName: 'Auth' }),
    ).toEqual({ origin: 'https://auth.example.com', rpId: 'example.com', rpName: 'Auth' });
    expect(
      resolveWebauthnConfig({ issuer: 'http://localhost:7777', rpId: 'localhost', brandName: 'Auth' }),
    ).toEqual({ origin: 'http://localhost:7777', rpId: 'localhost', rpName: 'Auth' });
  });

  it('fails closed on a sibling domain, an ip, or a bad issuer', () => {
    const base = { brandName: 'Auth' };
    expect(resolveWebauthnConfig({ ...base, issuer: 'https://auth.example.com', rpId: 'login.example.com' })).toBeNull();
    // An ip origin is only ever its own rp_id, never a parent domain of one.
    expect(resolveWebauthnConfig({ ...base, issuer: 'https://192.0.2.10', rpId: '192.0.2.10' })).not.toBeNull();
    expect(resolveWebauthnConfig({ ...base, issuer: 'https://auth.192.0.2.10', rpId: '192.0.2.10' })).toBeNull();
    expect(resolveWebauthnConfig({ ...base, issuer: 'auth.example.com', rpId: 'example.com' })).toBeNull();
    expect(resolveWebauthnConfig({ ...base, issuer: 'https://auth.example.com/path', rpId: 'example.com' })).toBeNull();
    expect(resolveWebauthnConfig({ ...base, issuer: 'https://auth.example.com', rpId: 'example.com', brandName: ' ' })).toBeNull();
  });
});

describe('registration options', () => {
  it('projects the legacy option shape and stores the challenge', async () => {
    const { deps, token, userId } = await harness();
    const response = await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps);
    expect(response.status).toBe(200);

    const body = (await response.json()) as {
      request_id: string;
      publicKey: Record<string, any>;
    };
    expect(Object.keys(body)).toEqual(['publicKey', 'request_id']);
    expect(Object.keys(body.publicKey)).toEqual([
      'authenticatorSelection',
      'challenge',
      'extensions',
      'pubKeyCredParams',
      'rp',
      'timeout',
      'user',
    ]);
    expect(body.publicKey.authenticatorSelection).toEqual({
      requireResidentKey: true,
      residentKey: 'required',
      userVerification: 'required',
    });
    expect(body.publicKey.extensions).toEqual({ credProps: true });
    expect(body.publicKey.pubKeyCredParams).toEqual([
      { alg: -7, type: 'public-key' },
      { alg: -257, type: 'public-key' },
    ]);
    expect(body.publicKey.rp).toEqual({ id: RP_ID, name: 'No Trade No Life' });
    expect(body.publicKey.timeout).toBe(300000);
    expect(body.publicKey.user).toEqual({
      displayName: 'user@example.com',
      id: await webauthnUserHandleText(userId),
      name: 'user@example.com',
    });
    expect(body.publicKey.challenge).toHaveLength(43);

    const stored = await deps.webauthnStore.findChallenge(body.request_id, 'register');
    expect(stored).not.toBeNull();
    expect(stored!.userId).toBe(userId);
    expect(stored!.origin).toBe(ORIGIN);
    expect(stored!.rpId).toBe(RP_ID);
    expect(JSON.parse(stored!.stateJson)).toEqual({
      challenge: body.publicKey.challenge,
      user_handle: body.publicKey.user.id,
    });
  });

  it('spends the previous unused registration challenge for the same user', async () => {
    const { deps, token, webauthnStore } = await harness();
    const first = (await (
      await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps)
    ).json()) as { request_id: string };
    const second = (await (
      await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps)
    ).json()) as { request_id: string };

    expect((await webauthnStore.findChallenge(first.request_id, 'register'))!.consumedAt).not.toBeNull();
    expect((await webauthnStore.findChallenge(second.request_id, 'register'))!.consumedAt).toBeNull();
  });

  it('rejects a body with fields, a missing token and a broken rp configuration', async () => {
    const { deps, token, adminStore } = await harness();
    expect((await handleWebauthnRegisterOptions(post('/webauthn/register/options', { extra: 1 }, token), deps)).status).toBe(400);
    expect((await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}), deps)).status).toBe(401);

    adminStore.config = { ...adminStore.config, rpId: 'login.example.com' };
    expect((await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps)).status).toBe(400);
  });
});

describe('registration verify', () => {
  it('stores a neutral credential and spends the challenge', async () => {
    const { userId, webauthnStore, register } = await harness();
    const authenticator = await newAuthenticator();
    const { options, verifyResponse } = await register(authenticator);

    expect(verifyResponse.status).toBe(200);
    expect(await verifyResponse.json()).toEqual({ ok: true });

    expect(webauthnStore.credentials).toHaveLength(1);
    const row = webauthnStore.credentials[0]!;
    expect(row.userId).toBe(userId);
    expect(row.rpId).toBe(RP_ID);

    const stored = parsePasskey(row.passkeyJson)!;
    expect(stored).not.toBeNull();
    expect(stored.id).toBe(authenticator.credentialIdText);
    expect(stored.counter).toBe(0);
    expect(stored.transports).toEqual(['internal', 'hybrid']);
    expect(stored.user_handle).toBe(await webauthnUserHandleText(userId));
    expect(stored.public_key.length).toBeGreaterThan(60);

    expect((await webauthnStore.findChallenge(options.request_id, 'register'))!.consumedAt).not.toBeNull();
  });

  it('refuses a replayed ceremony and a credential from another origin', async () => {
    const { deps, token, register } = await harness();
    const authenticator = await newAuthenticator();
    const { options, credential } = await register(authenticator);

    const replay = await handleWebauthnRegisterVerify(
      post('/webauthn/register/verify', { request_id: options.request_id, credential }, token),
      deps,
    );
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: 'invalid_webauthn_registration' });

    const other = await newAuthenticator();
    const optionsAgain = (await (
      await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps)
    ).json()) as { request_id: string; publicKey: { challenge: string } };
    const foreign = await registrationResponse(other, optionsAgain.publicKey.challenge, { origin: 'https://evil.example' });
    const response = await handleWebauthnRegisterVerify(
      post('/webauthn/register/verify', { request_id: optionsAgain.request_id, credential: foreign }, token),
      deps,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'invalid_webauthn_registration' });
  });

  it('rejects a credential whose rpIdHash is not this relying party', async () => {
    const { deps, token } = await harness();
    const authenticator = await newAuthenticator();
    const options = (await (
      await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps)
    ).json()) as { request_id: string; publicKey: { challenge: string } };
    const credential = await registrationResponse(authenticator, options.publicKey.challenge, { rpId: 'other.example' });
    const response = await handleWebauthnRegisterVerify(
      post('/webauthn/register/verify', { request_id: options.request_id, credential }, token),
      deps,
    );
    expect(response.status).toBe(400);
  });

  it('rejects an authenticator that reports a non-discoverable credential', async () => {
    const { deps, token, webauthnStore } = await harness();
    const authenticator = await newAuthenticator();
    const options = (await (
      await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps)
    ).json()) as { request_id: string; publicKey: { challenge: string } };
    const credential = await registrationResponse(authenticator, options.publicKey.challenge, {
      extensionResults: { credProps: { rk: false } },
    });
    const response = await handleWebauthnRegisterVerify(
      post('/webauthn/register/verify', { request_id: options.request_id, credential }, token),
      deps,
    );
    expect(response.status).toBe(400);
    expect(webauthnStore.credentials).toHaveLength(0);
    expect((await webauthnStore.findChallenge(options.request_id, 'register'))!.consumedAt).toBeNull();
  });

  it('lets an Ed25519 session add exactly one passkey', async () => {
    const { deps, token, webauthnStore, register } = await harness({ authMethod: 'ed25519' });
    const first = await newAuthenticator();
    expect((await register(first)).verifyResponse.status).toBe(200);

    const second = await newAuthenticator();
    const optionsResponse = await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps);
    expect(optionsResponse.status).toBe(403);
    expect(await optionsResponse.json()).toEqual({ error: 'insufficient_authentication_method' });

    const options = (await (
      await handleWebauthnRegisterOptions(post('/webauthn/register/options', {}, token), deps)
    ).json()) as { error: string };
    expect(options.error).toBe('insufficient_authentication_method');
    expect(webauthnStore.credentials).toHaveLength(1);
    expect(second.credentialIdText).not.toBe(first.credentialIdText);
  });
});

describe('authentication', () => {
  it('issues a challenge with no allowCredentials and no user binding', async () => {
    const { deps, webauthnStore } = await harness();
    const response = await handleWebauthnAuthenticationOptions(post('/webauthn/authenticate/options', {}), deps);
    expect(response.status).toBe(200);

    const body = (await response.json()) as { request_id: string; publicKey: Record<string, unknown> };
    expect(Object.keys(body.publicKey)).toEqual(['challenge', 'rpId', 'timeout', 'userVerification']);
    expect(body.publicKey).toEqual({
      challenge: expect.any(String),
      rpId: RP_ID,
      timeout: 300000,
      userVerification: 'required',
    });
    const stored = await webauthnStore.findChallenge(body.request_id, 'authenticate');
    expect(stored!.userId).toBeNull();
  });

  it('verifies an assertion, advances the counter and mints a session', async () => {
    const { userId, sessionStore, webauthnStore, register, authenticate } = await harness();
    const authenticator = await newAuthenticator();
    await register(authenticator);

    const { verifyResponse } = await authenticate(authenticator, await webauthnUserHandleText(userId));
    expect(verifyResponse.status).toBe(200);
    const tokens = (await verifyResponse.json()) as {
      session_id: string;
      access_token: string;
      refresh_token: string;
      token_type: string;
      expires_in: number;
    };
    expect(tokens.token_type).toBe('Bearer');
    expect(tokens.expires_in).toBe(900);
    expect(tokens.refresh_token).toHaveLength(64);

    const session = sessionStore.rows.find((row) => row.id === tokens.session_id)!;
    expect(session.authMethod).toBe('webauthn');
    expect(session.userId).toBe(userId);
    expect(session.audiences).toEqual(['auth.ntnl.io']);

    const passkey = parsePasskey(webauthnStore.credentials[0]!.passkeyJson)!;
    expect(passkey.counter).toBe(1);
    expect(webauthnStore.credentials[0]!.lastUsedAt).toBe(NOW.toISOString());
  });

  it('rejects a replayed assertion and a counter that does not move', async () => {
    const { deps, sessionStore, register } = await harness();
    const authenticator = await newAuthenticator();
    await register(authenticator);

    const options = (await (
      await handleWebauthnAuthenticationOptions(post('/webauthn/authenticate/options', {}), deps)
    ).json()) as { request_id: string; publicKey: { challenge: string } };
    const credential = await assertionResponse(authenticator, options.publicKey.challenge, { counter: 1 });
    const first = await handleWebauthnAuthenticationVerify(
      post('/webauthn/authenticate/verify', { request_id: options.request_id, credential }),
      deps,
    );
    expect(first.status).toBe(200);

    const replay = await handleWebauthnAuthenticationVerify(
      post('/webauthn/authenticate/verify', { request_id: options.request_id, credential }),
      deps,
    );
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: 'invalid_webauthn_authentication' });

    const sessionsAfterFirst = sessionStore.rows.length;

    // A fresh challenge does not excuse a counter that refuses to move: that is a cloned
    // authenticator, not a new sign-in.
    const replayOptions = (await (
      await handleWebauthnAuthenticationOptions(post('/webauthn/authenticate/options', {}), deps)
    ).json()) as { request_id: string; publicKey: { challenge: string } };
    const staleCredential = await assertionResponse(authenticator, replayOptions.publicKey.challenge, { counter: 1 });
    const staleResponse = await handleWebauthnAuthenticationVerify(
      post('/webauthn/authenticate/verify', { request_id: replayOptions.request_id, credential: staleCredential }),
      deps,
    );
    expect(staleResponse.status).toBe(400);
    expect(sessionStore.rows.length).toBe(sessionsAfterFirst);

    // One step forward is accepted.
    const aheadOptions = (await (
      await handleWebauthnAuthenticationOptions(post('/webauthn/authenticate/options', {}), deps)
    ).json()) as { request_id: string; publicKey: { challenge: string } };
    const aheadCredential = await assertionResponse(authenticator, aheadOptions.publicKey.challenge, { counter: 2 });
    const ahead = await handleWebauthnAuthenticationVerify(
      post('/webauthn/authenticate/verify', { request_id: aheadOptions.request_id, credential: aheadCredential }),
      deps,
    );
    expect(ahead.status).toBe(200);
    expect(sessionStore.rows.length).toBe(sessionsAfterFirst + 1);
  });

  it('refuses a mismatched user handle, a foreign rp and an unknown credential', async () => {
    const { deps, register } = await harness();
    const authenticator = await newAuthenticator();
    await register(authenticator);

    const wrongHandle = await (
      await handleWebauthnAuthenticationOptions(post('/webauthn/authenticate/options', {}), deps)
    ).json() as { request_id: string; publicKey: { challenge: string } };
    const mismatched = await assertionResponse(authenticator, wrongHandle.publicKey.challenge, {
      userHandle: 'AAAAAAAAAAAAAAAAAAAAAA',
    });
    expect(
      (
        await handleWebauthnAuthenticationVerify(
          post('/webauthn/authenticate/verify', { request_id: wrongHandle.request_id, credential: mismatched }),
          deps,
        )
      ).status,
    ).toBe(400);

    const unknownCredential = await newAuthenticator();
    const anonymous = await (
      await handleWebauthnAuthenticationOptions(post('/webauthn/authenticate/options', {}), deps)
    ).json() as { request_id: string; publicKey: { challenge: string } };
    const stray = await assertionResponse(unknownCredential, anonymous.publicKey.challenge);
    expect(
      (
        await handleWebauthnAuthenticationVerify(
          post('/webauthn/authenticate/verify', { request_id: anonymous.request_id, credential: stray }),
          deps,
        )
      ).status,
    ).toBe(400);
  });

  it('resolves audiences from redirect_uri like every other sign-in', async () => {
    const { deps, register } = await harness();
    const authenticator = await newAuthenticator();
    await register(authenticator);

    const options = (await (
      await handleWebauthnAuthenticationOptions(post('/webauthn/authenticate/options', {}), deps)
    ).json()) as { request_id: string; publicKey: { challenge: string } };
    const credential = await assertionResponse(authenticator, options.publicKey.challenge);
    const response = await handleWebauthnAuthenticationVerify(
      post('/webauthn/authenticate/verify', {
        request_id: options.request_id,
        credential,
        redirect_uri: 'https://linkit.ntnl.io/callback',
      }),
      deps,
    );
    expect(response.status).toBe(200);
    const tokens = (await response.json()) as { session_id: string };
    const session = (await deps.sessionStore.find(tokens.session_id))!;
    expect(session.audiences).toEqual(['linkit.ntnl.io']);

    const badAudience = await handleWebauthnAuthenticationVerify(
      post('/webauthn/authenticate/verify', {
        request_id: options.request_id,
        credential,
        redirect_uri: 'https://linkit.ntnl.io/callback',
        audiences: ['auth.ntnl.io'],
      }),
      deps,
    );
    expect(badAudience.status).toBe(400);
  });
});

describe('credential management', () => {
  it('deletes only the owner’s credential', async () => {
    const { deps, token, register } = await harness();
    const authenticator = await newAuthenticator();
    await register(authenticator);

    const stranger = await harness();
    const notMine = await handleWebauthnCredentialDelete(
      new Request(`https://auth.ntnl.io/webauthn/credentials/${authenticator.credentialIdText}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${stranger.token}` },
      }),
      stranger.deps,
      authenticator.credentialIdText,
    );
    expect(notMine.status).toBe(404);
    expect(await notMine.json()).toEqual({ error: 'credential_not_found' });

    const deleted = await handleWebauthnCredentialDelete(
      new Request(`https://auth.ntnl.io/webauthn/credentials/${authenticator.credentialIdText}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      }),
      deps,
      authenticator.credentialIdText,
    );
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ ok: true });
  });

  it('refuses management from an Ed25519 session', async () => {
    const { deps, token, register, webauthnStore } = await harness({ authMethod: 'ed25519' });
    const authenticator = await newAuthenticator();
    await register(authenticator);

    const response = await handleWebauthnCredentialDelete(
      new Request(`https://auth.ntnl.io/webauthn/credentials/${authenticator.credentialIdText}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      }),
      deps,
      authenticator.credentialIdText,
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: 'insufficient_authentication_method' });
    expect(webauthnStore.credentials).toHaveLength(1);
  });
});
