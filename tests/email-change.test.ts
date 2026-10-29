import { describe, expect, it } from 'vitest';
import { ensureSigningKeys } from '../src/jwks';
import type { SmtpConfig } from '../src/mail/config';
import type { MailContent } from '../src/mail/message';
import type { EmailChangeDeps } from '../src/routes/email-change';
import { handleEmailChangeStart, handleEmailChangeVerify } from '../src/routes/email-change';
import { mintSession } from '../src/session';
import {
  MemoryCredentialStore,
  MemoryEmailChangeStore,
  MemoryKeyStore,
  MemoryMailTemplateStore,
  MemorySessionStore,
  MemoryUserStore,
} from './doubles';

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

async function harness(
  options: {
    smtp?: SmtpConfig[];
    mailTemplates?: MemoryMailTemplateStore;
    sendMail?: (config: SmtpConfig, to: string, content: MailContent) => Promise<void>;
  } = {},
) {
  const keyStore = new MemoryKeyStore();
  await ensureSigningKeys(keyStore);
  const sessionStore = new MemorySessionStore();
  const userStore = new MemoryUserStore();
  const emailChangeStore = new MemoryEmailChangeStore();
  const sent: Array<{ to: string; subject: string; text: string }> = [];

  const userId = await userStore.ensureByEmail('old@example.com', NOW.toISOString());
  emailChangeStore.taken.add('old@example.com');

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
    isAdmin: false,
    now: NOW,
  });

  const deps: EmailChangeDeps = {
    issuer: ISSUER,
    keyStore,
    sessionStore,
    userStore,
    credentialStore: new MemoryCredentialStore(),
    now: NOW,
    emailChangeStore,
    smtpStore: { listActive: async () => options.smtp ?? [smtpConfig] },
    mailTemplates: options.mailTemplates ?? new MemoryMailTemplateStore(),
    sendMail:
      options.sendMail ??
      (async (_config, to, content) => {
        sent.push({ to, subject: content.subject, text: content.text });
      }),
    draw: 0,
  };

  function post(path: string, body: unknown, token: string | null = pair.accessToken): Request {
    return new Request(`${ISSUER}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(token === null ? {} : { authorization: `Bearer ${token}` }),
      },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    });
  }

  function codeFromLastMail(): string {
    const match = /(\d{6})/.exec(sent[sent.length - 1]!.text);
    if (!match) throw new Error('no code in the mail');
    return match[1]!;
  }

  return { deps, userId, emailChangeStore, userStore, sent, post, codeFromLastMail };
}

describe('POST /me/email/start', () => {
  it('mails a code to the normalized new address and keeps only its hash', async () => {
    const { deps, userId, emailChangeStore, sent, post, codeFromLastMail } = await harness();

    const response = await handleEmailChangeStart(post('/me/email/start', { email: '  New@Example.COM ' }), deps);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });

    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe('new@example.com');
    expect(sent[0]!.subject).toBe('Confirm your auth-mini email change');

    const row = emailChangeStore.rows.get(userId)!;
    expect(row.email).toBe('new@example.com');
    expect(row.consumedAt).toBeNull();
    expect(row.expiresAt).toBe(new Date(NOW.getTime() + 600_000).toISOString());
    expect(row.codeHash).not.toBe(codeFromLastMail());
    expect(row.codeHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('uses the email-change template, not the login one', async () => {
    const templates = new MemoryMailTemplateStore();
    templates.brandName = 'No Trade No Life';
    templates.overrides = {
      loginSubject: 'login subject',
      loginText: 'login {code}',
      emailChangeSubject: '{brand}: confirm the new address',
      emailChangeText: 'Move to the new address with {code}.',
    };

    const { deps, sent, post } = await harness({ mailTemplates: templates });
    const response = await handleEmailChangeStart(post('/me/email/start', { email: 'new@example.com' }), deps);

    expect(response.status).toBe(200);
    expect(sent[0]!.subject).toBe('No Trade No Life: confirm the new address');
    expect(sent[0]!.text).toMatch(/^Move to the new address with \d{6}\.$/);
  });

  it('refuses an address another account owns', async () => {
    const { deps, emailChangeStore, sent, post } = await harness();
    emailChangeStore.taken.add('taken@example.com');

    const response = await handleEmailChangeStart(post('/me/email/start', { email: 'taken@example.com' }), deps);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: 'email_already_in_use' });
    expect(sent).toHaveLength(0);
    expect(emailChangeStore.rows.size).toBe(0);
  });

  it('reports a missing or broken SMTP path instead of pretending to send', async () => {
    const unconfigured = await harness({ smtp: [] });
    const missing = await handleEmailChangeStart(
      unconfigured.post('/me/email/start', { email: 'new@example.com' }),
      unconfigured.deps,
    );
    expect(missing.status).toBe(503);
    expect(await missing.json()).toEqual({ error: 'smtp_not_configured' });
    expect(unconfigured.emailChangeStore.rows.size).toBe(0);

    const broken = await harness({
      sendMail: async () => {
        throw new Error('smtp said no');
      },
    });
    const failed = await handleEmailChangeStart(broken.post('/me/email/start', { email: 'new@example.com' }), broken.deps);
    expect(failed.status).toBe(503);
    expect(await failed.json()).toEqual({ error: 'smtp_temporarily_unavailable' });
    // A code the user cannot have received must not stay usable.
    expect(broken.emailChangeStore.rows.get(broken.userId)!.consumedAt).not.toBeNull();
  });

  it('rejects a malformed body and a missing token', async () => {
    const { deps, post } = await harness();
    for (const body of [{}, { email: 'not-an-address' }, { email: 'a@b.c', extra: 1 }, { email: 42 }]) {
      expect((await handleEmailChangeStart(post('/me/email/start', body), deps)).status, JSON.stringify(body)).toBe(400);
    }
    const anonymous = await handleEmailChangeStart(post('/me/email/start', { email: 'new@example.com' }, null), deps);
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toEqual({ error: 'invalid_access_token' });
  });
});

describe('POST /me/email/verify', () => {
  it('moves the address and stamps the verification time', async () => {
    const { deps, userId, emailChangeStore, post, codeFromLastMail } = await harness();
    await handleEmailChangeStart(post('/me/email/start', { email: 'new@example.com' }), deps);
    const code = codeFromLastMail();

    const response = await handleEmailChangeVerify(post('/me/email/verify', { email: 'new@example.com', code }), deps);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(emailChangeStore.assigned.get(userId)).toEqual({ email: 'new@example.com', at: NOW.toISOString() });

    // The code is spent: a replay cannot move the address twice.
    const replay = await handleEmailChangeVerify(post('/me/email/verify', { email: 'new@example.com', code }), deps);
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({ error: 'invalid_email_change_otp' });
  });

  it('refuses a wrong code, a different address and an expired code alike', async () => {
    const { deps, userId, emailChangeStore, post, codeFromLastMail } = await harness();
    await handleEmailChangeStart(post('/me/email/start', { email: 'new@example.com' }), deps);
    const code = codeFromLastMail();
    const wrongCode = code === '000000' ? '111111' : '000000';

    const wrong = await handleEmailChangeVerify(post('/me/email/verify', { email: 'new@example.com', code: wrongCode }), deps);
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toEqual({ error: 'invalid_email_change_otp' });

    // A valid code cannot be spent on an address it was not issued for.
    const otherAddress = await handleEmailChangeVerify(post('/me/email/verify', { email: 'other@example.com', code }), deps);
    expect(otherAddress.status).toBe(401);

    emailChangeStore.rows.get(userId)!.expiresAt = new Date(NOW.getTime() - 1000).toISOString();
    const expired = await handleEmailChangeVerify(post('/me/email/verify', { email: 'new@example.com', code }), deps);
    expect(expired.status).toBe(401);
    expect(emailChangeStore.assigned.size).toBe(0);
  });

  it('refuses an address that was claimed between start and verify', async () => {
    const { deps, emailChangeStore, post, codeFromLastMail } = await harness();
    await handleEmailChangeStart(post('/me/email/start', { email: 'new@example.com' }), deps);
    const code = codeFromLastMail();
    emailChangeStore.taken.add('new@example.com');

    const response = await handleEmailChangeVerify(post('/me/email/verify', { email: 'new@example.com', code }), deps);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: 'email_already_in_use' });
    expect(emailChangeStore.assigned.size).toBe(0);
  });

  it('rejects a non-six-digit code, a malformed body and a missing token', async () => {
    const { deps, post } = await harness();
    for (const body of [
      { email: 'new@example.com', code: '12345' },
      { email: 'new@example.com', code: 'abcdef' },
      { email: 'bad', code: '123456' },
      { email: 'new@example.com' },
      { email: 'new@example.com', code: '123456', extra: true },
    ]) {
      expect((await handleEmailChangeVerify(post('/me/email/verify', body), deps)).status, JSON.stringify(body)).toBe(400);
    }
    const anonymous = await handleEmailChangeVerify(post('/me/email/verify', { email: 'new@example.com', code: '123456' }, null), deps);
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toEqual({ error: 'invalid_access_token' });
  });
});
