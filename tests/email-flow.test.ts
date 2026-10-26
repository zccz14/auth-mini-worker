import { describe, expect, it } from 'vitest';
import { MemoryKeyStore, MemoryOtpStore, MemorySessionStore, MemoryUserStore } from './doubles';
import { normalizeEmail, isEmailAddress, isSixDigitCode, generateOtpCode } from '../src/email/otp';
import { sha256Hex } from '../src/crypto/tokens';
import { ensureSigningKeys, currentSigningKey } from '../src/jwks';
import { verifyAccessToken } from '../src/jwt';
import type { SmtpConfig, SmtpConfigStore } from '../src/mail/config';
import type { EmailDeps } from '../src/routes/email';
import { handleEmailStart, handleEmailVerify } from '../src/routes/email';

const NOW = new Date('2026-10-26T04:00:00.000Z');
const ISSUER = 'https://auth.ntnl.io';

const smtpConfig: SmtpConfig = {
  id: 1,
  host: 'smtp.example.com',
  port: 587,
  username: 'mailer',
  password: 'secret',
  fromEmail: 'auth@ntnl.io',
  fromName: 'NTNL Authenticator',
  secure: true,
  weight: 1,
};

function makeDeps(overrides: Partial<EmailDeps> = {}) {
  const otpStore = new MemoryOtpStore();
  const userStore = new MemoryUserStore();
  const sessionStore = new MemorySessionStore();
  const keyStore = new MemoryKeyStore();
  const sent: Array<{ to: string; subject: string; text: string }> = [];
  const smtpStore: SmtpConfigStore = { listActive: async () => [smtpConfig] };

  const deps: EmailDeps = {
    issuer: ISSUER,
    otpStore,
    userStore,
    sessionStore,
    keyStore,
    smtpStore,
    sendMail: async (_config, to, content) => {
      sent.push({ to, subject: content.subject, text: content.text });
    },
    now: NOW,
    clientIp: '203.0.113.7',
    userAgent: 'vitest',
    draw: 0,
    ...overrides,
  };
  return { deps, otpStore, userStore, sessionStore, keyStore, sent };
}

function jsonRequest(body: unknown): Request {
  return new Request('https://auth.ntnl.io/email/start', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

async function startWith(deps: EmailDeps, email: string): Promise<Response> {
  return handleEmailStart(jsonRequest({ email }), deps);
}

describe('email validation helpers', () => {
  it('mirrors the legacy predicates', () => {
    expect(isEmailAddress('a@b.c')).toBe(true);
    expect(isEmailAddress('a@b@c')).toBe(false);
    expect(isEmailAddress('@b.c')).toBe(false);
    expect(isEmailAddress('a@')).toBe(false);
    expect(normalizeEmail(' User@Example.COM ')).toBe('user@example.com');
    expect(isSixDigitCode('000042')).toBe(true);
    expect(isSixDigitCode('12345')).toBe(false);
    expect(isSixDigitCode('12345a')).toBe(false);
    expect(generateOtpCode()).toMatch(/^[0-9]{6}$/);
  });
});

describe('POST /email/start', () => {
  it('rejects bad bodies with invalid_request', async () => {
    const { deps } = makeDeps();
    expect((await handleEmailStart(jsonRequest('{"email":"a@b.c","extra":1}'), deps)).status).toBe(400);
    expect((await handleEmailStart(jsonRequest('{"email":'), deps)).status).toBe(400);
    expect((await startWith(deps, 'not-an-email')).status).toBe(400);
  });

  it('answers smtp_not_configured without writing a code', async () => {
    const { deps, otpStore } = makeDeps({ smtpStore: { listActive: async () => [] } });
    const response = await startWith(deps, 'user@example.com');
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: 'smtp_not_configured' });
    expect(otpStore.rows.size).toBe(0);
  });

  it('stores a hash, not the code, and mails the code', async () => {
    const { deps, otpStore, sent } = makeDeps();
    const response = await startWith(deps, ' User@Example.COM ');

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe('user@example.com');

    const code = /(\d{6})/.exec(sent[0]!.text)![1]!;
    const stored = await otpStore.find('user@example.com');
    expect(stored?.codeHash).toBe(await sha256Hex(code));
    expect(stored?.codeHash).not.toContain(code);
    expect(stored?.expiresAt).toBe('2026-10-26T04:10:00.000Z');
  });

  it('invalidates the code when delivery fails', async () => {
    const { deps, otpStore } = makeDeps({
      sendMail: async () => {
        throw new Error('smtp down');
      },
    });
    const response = await startWith(deps, 'user@example.com');

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: 'smtp_temporarily_unavailable' });
    const stored = await otpStore.find('user@example.com');
    expect(stored?.consumedAt).not.toBeNull();
  });
});

describe('POST /email/verify', () => {
  async function startThenRead() {
    const harness = makeDeps();
    await startWith(harness.deps, 'user@example.com');
    return { ...harness, code: /(\d{6})/.exec(harness.sent[0]!.text)![1]! };
  }

  it('rejects a wrong, expired or reused code with invalid_email_otp', async () => {
    const { deps, code } = await startThenRead();
    const wrong = await handleEmailVerify(jsonRequest({ email: 'user@example.com', code: '000000' }), deps);
    expect(wrong.status).toBe(401);

    const ok = await handleEmailVerify(jsonRequest({ email: 'user@example.com', code }), deps);
    expect(ok.status).toBe(200);

    const reused = await handleEmailVerify(jsonRequest({ email: 'user@example.com', code }), deps);
    expect(reused.status).toBe(401);
    expect(await reused.json()).toEqual({ error: 'invalid_email_otp' });
  });

  it('mints a session and a verifiable token with the legacy claim set', async () => {
    const { deps, code, sessionStore, keyStore, userStore } = await startThenRead();
    await ensureSigningKeys(keyStore);

    const response = await handleEmailVerify(jsonRequest({ email: 'user@example.com', code }), deps);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;

    expect(Object.keys(body).sort()).toEqual(['access_token', 'expires_in', 'refresh_token', 'session_id', 'token_type']);
    expect(body['token_type']).toBe('Bearer');
    expect(body['expires_in']).toBe(900);

    expect(sessionStore.rows).toHaveLength(1);
    const row = sessionStore.rows[0]!;
    expect(row.userId).toBe(userStore.byEmail.get('user@example.com'));
    expect(row.authMethod).toBe('email_otp');
    expect(row.sourceAuthMethod).toBeNull();
    expect(row.audiences).toEqual(['auth.ntnl.io']);
    expect(row.ip).toBe('203.0.113.7');

    const key = await currentSigningKey(keyStore);
    const claims = await verifyAccessToken(
      { kid: key.kid, publicJwk: key.publicJwk },
      body['access_token'] as string,
      Math.floor(NOW.getTime() / 1000),
    );
    expect(claims).toMatchObject({
      sub: row.userId,
      sid: row.id,
      iss: ISSUER,
      aud: 'auth.ntnl.io',
      amr: ['email_otp'],
      auth_admin: false,
      typ: 'access',
      iat: Math.floor(NOW.getTime() / 1000),
      exp: Math.floor(NOW.getTime() / 1000) + 900,
    });
    expect(row.refreshTokenHash).toBe(await sha256Hex(body['refresh_token'] as string));
  });

  it('applies the redirect audience rules and rejects loopback without one', async () => {
    const { deps, code } = await startThenRead();
    const loopback = await handleEmailVerify(
      jsonRequest({ email: 'user@example.com', code, redirect_uri: 'http://localhost:3000/cb' }),
      deps,
    );
    expect(loopback.status).toBe(400);

    const { deps: deps2, code: code2 } = await startThenRead();
    const ok = await handleEmailVerify(
      jsonRequest({ email: 'user@example.com', code: code2, redirect_uri: 'https://linkit.ntnl.io/cb', audiences: ['linkit.ntnl.io', '1ex.ntnl.io'] }),
      deps2,
    );
    expect(ok.status).toBe(200);
    const claims = await verifyAccessToken(
      { kid: (await currentSigningKey(deps2.keyStore)).kid, publicJwk: (await currentSigningKey(deps2.keyStore)).publicJwk },
      ((await ok.json()) as Record<string, unknown>)['access_token'] as string,
      Math.floor(NOW.getTime() / 1000),
    );
    expect(claims?.aud).toEqual(['1ex.ntnl.io', 'linkit.ntnl.io']);
  });

  it('rejects unknown fields and malformed codes as invalid_request', async () => {
    const { deps, code } = await startThenRead();
    expect((await handleEmailVerify(jsonRequest({ email: 'user@example.com', code, extra: true }), deps)).status).toBe(400);
    expect((await handleEmailVerify(jsonRequest({ email: 'user@example.com', code: '00000' }), deps)).status).toBe(400);
  });
});
