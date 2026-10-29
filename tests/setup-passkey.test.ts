import { describe, expect, it } from 'vitest';
import { ensureSigningKeys } from '../src/jwks';
import type { AdminDeps } from '../src/routes/admin';
import {
  handleAdminSetup,
  handleAdminSetupPasskey,
  handleAdminSetupPasskeyOptions,
} from '../src/routes/admin';
import type { WebauthnDeps } from '../src/routes/webauthn';
import {
  handleWebauthnAuthenticationOptions,
  handleWebauthnAuthenticationVerify,
} from '../src/routes/webauthn';
import { deriveSetupRelyingParty } from '../src/admin/validate';
import { parsePasskey, webauthnUserHandleText } from '../src/webauthn';
import {
  MemoryAdminStore,
  MemoryCredentialStore,
  MemoryKeyStore,
  MemoryMailTemplateStore,
  MemoryRequestStatsStore,
  MemorySessionStore,
  MemoryUserStore,
  MemoryWebauthnStore,
} from './doubles';
import { assertionResponse, newAuthenticator, registrationResponse } from './software-authenticator';

const NOW = new Date('2026-10-26T10:00:00.000Z');
const ISSUER = 'https://auth.ntnl.io';
const RP_ID = 'auth.ntnl.io';

function request(
  base: string,
  method: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Request {
  return new Request(`${base}/admin/setup`, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

function optionsRequest(base = ISSUER, headers: Record<string, string> = {}): Request {
  return new Request(`${base}/admin/setup/passkey/options`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: '{}',
  });
}

async function harness(options: { setupToken?: string | null } = {}) {
  const keyStore = new MemoryKeyStore();
  await ensureSigningKeys(keyStore);
  const sessionStore = new MemorySessionStore();
  const userStore = new MemoryUserStore();
  const webauthnStore = new MemoryWebauthnStore();
  const adminStore = new MemoryAdminStore();
  // A database straight out of the migration: nothing is claimed and it still says localhost.
  adminStore.config = {
    issuer: 'http://localhost:7777',
    rpId: 'localhost',
    brandName: 'No Trade No Life',
    brandBackgroundImage: '',
    adminUserId: null,
  };

  const deps: AdminDeps = {
    issuer: ISSUER,
    keyStore,
    sessionStore,
    userStore,
    credentialStore: new MemoryCredentialStore(),
    adminStore,
    webauthnStore,
    requestStatsStore: new MemoryRequestStatsStore(),
    mailTemplates: new MemoryMailTemplateStore(),
    setupToken: options.setupToken ?? null,
    now: NOW,
  };

  /** Options then verify, the way the setup page does it. */
  async function claim(target: AdminDeps, base = ISSUER) {
    const optionsResponse = await handleAdminSetupPasskeyOptions(optionsRequest(base), target);
    const optionsBody = (await optionsResponse.json()) as {
      request_id: string;
      publicKey: { challenge: string; user: { id: string } };
    };
    const authenticator = await newAuthenticator();
    const credential = await registrationResponse(authenticator, optionsBody.publicKey.challenge);
    const verifyResponse = await handleAdminSetupPasskey(
      request(base, 'PUT', {
        request_id: optionsBody.request_id,
        credential,
        issuer: new URL(base).origin,
        rp_id: new URL(base).hostname,
      }),
      target,
    );
    return { optionsResponse, optionsBody, authenticator, credential, verifyResponse };
  }

  return { deps, keyStore, sessionStore, userStore, webauthnStore, adminStore, claim };
}

describe('deriveSetupRelyingParty', () => {
  it('binds a claim to the host the browser actually reached', () => {
    expect(deriveSetupRelyingParty('https://auth-demo.ntnl.io/admin/setup')).toEqual({
      issuer: 'https://auth-demo.ntnl.io',
      rpId: 'auth-demo.ntnl.io',
    });
    // `wrangler dev` has to work too, and WebAuthn treats localhost as a secure context.
    expect(deriveSetupRelyingParty('http://localhost:8787/admin/setup')).toEqual({
      issuer: 'http://localhost:8787',
      rpId: 'localhost',
    });
  });

  it('refuses an address a passkey could never be bound to', () => {
    // An IP literal, a single-label host and a non-http scheme all fail closed: claiming one
    // would pin rp_id to something no authenticator accepts, with no way back without a token.
    expect(deriveSetupRelyingParty('https://192.0.2.10/admin/setup')).toBeNull();
    expect(deriveSetupRelyingParty('https://intranet/admin/setup')).toBeNull();
    expect(deriveSetupRelyingParty('https://[::1]/admin/setup')).toBeNull();
    expect(deriveSetupRelyingParty('ftp://auth.ntnl.io/admin/setup')).toBeNull();
  });
});

describe('POST /admin/setup/passkey/options', () => {
  it('creates the root user the challenge needs and reuses an abandoned attempt', async () => {
    const { deps, webauthnStore } = await harness();

    const first = await handleAdminSetupPasskeyOptions(optionsRequest(), deps);
    expect(first.status).toBe(200);
    const body = (await first.json()) as {
      request_id: string;
      publicKey: Record<string, any>;
    };
    // The option projection is the same one the authenticated route emits.
    expect(Object.keys(body)).toEqual(['publicKey', 'request_id']);
    expect(body.publicKey.rp).toEqual({ id: RP_ID, name: 'No Trade No Life' });
    expect(body.publicKey.authenticatorSelection).toEqual({
      requireResidentKey: true,
      residentKey: 'required',
      userVerification: 'required',
    });

    const rootUserId = (await deps.adminStore.ensureRootUser());
    expect(body.publicKey.user.id).toBe(await webauthnUserHandleText(rootUserId));

    const stored = await webauthnStore.findChallenge(body.request_id, 'register');
    expect(stored).not.toBeNull();
    expect(stored!.userId).toBe(rootUserId);
    expect(stored!.origin).toBe(ISSUER);
    expect(stored!.rpId).toBe(RP_ID);

    // A retry before the ceremony finishes must not leave a second email-less ghost behind.
    const second = await handleAdminSetupPasskeyOptions(optionsRequest(), deps);
    const secondBody = (await second.json()) as { publicKey: { user: { id: string } } };
    expect(secondBody.publicKey.user.id).toBe(body.publicKey.user.id);
    expect((await webauthnStore.findChallenge(body.request_id, 'register'))!.consumedAt).not.toBeNull();
  });

  it('refuses every address a passkey cannot be bound to, and any claimed instance', async () => {
    const { deps } = await harness();
    expect((await handleAdminSetupPasskeyOptions(optionsRequest('https://192.0.2.10'), deps)).status).toBe(400);

    const allowed = await handleAdminSetupPasskeyOptions(optionsRequest(), deps);
    expect(allowed.status).toBe(200);

    await deps.adminStore.claimRootUser('root-user', { issuer: ISSUER, rpId: RP_ID });
    const claimed = await handleAdminSetupPasskeyOptions(optionsRequest(), deps);
    expect(claimed.status).toBe(403);
    expect(await claimed.json()).toEqual({ error: 'admin_setup_forbidden' });
  });

  it('rejects a body with fields and a missing setup token', async () => {
    const { deps } = await harness();
    const extra = await handleAdminSetupPasskeyOptions(
      new Request(`${ISSUER}/admin/setup/passkey/options`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ rp_id: RP_ID }),
      }),
      deps,
    );
    expect(extra.status).toBe(400);

    const { deps: guarded } = await harness({ setupToken: 'shhh' });
    const denied = await handleAdminSetupPasskeyOptions(optionsRequest(), guarded);
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: 'admin_setup_token_required' });
    expect((await handleAdminSetupPasskeyOptions(optionsRequest(ISSUER, { 'x-admin-setup-token': 'shhh' }), guarded)).status).toBe(200);
  });
});

describe('PUT /admin/setup', () => {
  it('stores the passkey and only then makes that user the administrator', async () => {
    const { deps, webauthnStore, adminStore, claim } = await harness();
    const { optionsBody, authenticator, verifyResponse } = await claim(deps);

    expect(verifyResponse.status).toBe(200);
    expect(await verifyResponse.json()).toEqual({ ok: true });

    const rootUserId = adminStore.config.adminUserId!;
    expect(rootUserId).not.toBeNull();
    // The origin the request arrived on is what the passkey is bound to from now on.
    expect(adminStore.config.issuer).toBe(ISSUER);
    expect(adminStore.config.rpId).toBe(RP_ID);

    const row = webauthnStore.credentials[0]!;
    expect(row.userId).toBe(rootUserId);
    expect(row.rpId).toBe(RP_ID);
    const stored = parsePasskey(row.passkeyJson)!;
    expect(stored.id).toBe(authenticator.credentialIdText);
    expect(stored.user_handle).toBe(await webauthnUserHandleText(rootUserId));
    expect((await webauthnStore.findChallenge(optionsBody.request_id, 'register'))!.consumedAt).not.toBeNull();

    // One-shot: the probe reports "already done" and a second claim is refused.
    expect((await handleAdminSetup(request(ISSUER, 'GET'), deps)).status).toBe(403);
    const again = await handleAdminSetupPasskey(
      request(ISSUER, 'PUT', { request_id: optionsBody.request_id, credential: {} }),
      deps,
    );
    expect(again.status).toBe(409);
    expect(await again.json()).toEqual({ error: 'already_initialized' });
  });

  it('refuses a credential minted for another origin', async () => {
    const { deps, webauthnStore, adminStore } = await harness();
    const optionsResponse = await handleAdminSetupPasskeyOptions(optionsRequest(), deps);
    const options = (await optionsResponse.json()) as { request_id: string; publicKey: { challenge: string } };
    const authenticator = await newAuthenticator();
    const foreign = await registrationResponse(authenticator, options.publicKey.challenge, {
      origin: 'https://evil.example',
    });

    const response = await handleAdminSetupPasskey(
      request(ISSUER, 'PUT', { request_id: options.request_id, credential: foreign }),
      deps,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'invalid_webauthn_registration' });
    expect(adminStore.config.adminUserId).toBeNull();
    expect(webauthnStore.credentials).toHaveLength(0);
  });

  it('refuses a page that confirmed a different origin than the one it reached', async () => {
    const { deps } = await harness();
    const optionsResponse = await handleAdminSetupPasskeyOptions(optionsRequest(), deps);
    const options = (await optionsResponse.json()) as { request_id: string; publicKey: { challenge: string } };
    const authenticator = await newAuthenticator();
    const credential = await registrationResponse(authenticator, options.publicKey.challenge);

    const response = await handleAdminSetupPasskey(
      request(ISSUER, 'PUT', { request_id: options.request_id, credential, rp_id: 'auth-demo.ntnl.io' }),
      deps,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'invalid_request' });
  });

  it('rejects malformed bodies and a host that is not a DNS name', async () => {
    const { deps } = await harness();
    expect((await handleAdminSetupPasskey(request(ISSUER, 'PUT', { request_id: 'nope' }), deps)).status).toBe(400);
    expect((await handleAdminSetupPasskey(request('https://192.0.2.10', 'PUT', {}), deps)).status).toBe(400);
  });

  it('lets the freshly claimed passkey sign in as the administrator', async () => {
    const { deps, sessionStore, userStore, adminStore, claim } = await harness();
    const { authenticator, verifyResponse } = await claim(deps);
    expect(verifyResponse.status).toBe(200);

    // In D1 `isAdmin` reads `app_meta.admin_user_id`; the double keeps its own field.
    const rootUserId = adminStore.config.adminUserId!;
    userStore.adminId = rootUserId;

    const webauthnDeps: WebauthnDeps = { ...deps, clientIp: null, userAgent: 'vitest' };
    const optionsResponse = await handleWebauthnAuthenticationOptions(
      new Request(`${ISSUER}/webauthn/authenticate/options`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      }),
      webauthnDeps,
    );
    const options = (await optionsResponse.json()) as { request_id: string; publicKey: { challenge: string } };
    const assertion = await assertionResponse(authenticator, options.publicKey.challenge, {
      userHandle: await webauthnUserHandleText(rootUserId),
    });
    const verify = await handleWebauthnAuthenticationVerify(
      new Request(`${ISSUER}/webauthn/authenticate/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ request_id: options.request_id, credential: assertion }),
      }),
      webauthnDeps,
    );
    expect(verify.status).toBe(200);
    expect(sessionStore.rows).toHaveLength(1);
    expect(sessionStore.rows[0]!.userId).toBe(rootUserId);
    expect(sessionStore.rows[0]!.authMethod).toBe('webauthn');
  });
});
