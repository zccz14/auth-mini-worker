import { describe, expect, it } from 'vitest';
import { pickWeighted } from '../src/mail/config';
import type { SmtpConfig } from '../src/mail/config';
import { buildMimeMessage, otpMail, rfc2822Date } from '../src/mail/message';

const config: SmtpConfig = {
  id: 1,
  host: 'smtp.example.com',
  port: 587,
  username: 'mailer',
  password: 'secret',
  fromEmail: 'noreply@example.com',
  fromName: 'Auth Mini',
  secure: false,
  weight: 1,
};

function bodyOf(message: string): string {
  const [, body] = message.split('\r\n\r\n') as [string, string];
  return atob(body.replace(/\r\n/g, ''));
}

describe('mail message', () => {
  it('builds the legacy OTP mail', () => {
    const content = otpMail('123456');
    expect(content.subject).toBe('Your auth-mini verification code');
    expect(content.text).toBe('Your verification code is 123456. It expires in 10 minutes.');
  });

  it('emits a decodable text/plain message with a message id', () => {
    const message = buildMimeMessage(config, 'user@example.com', otpMail('000042'), new Date('2026-10-26T03:00:00Z'));
    expect(message).toContain('From: Auth Mini <noreply@example.com>');
    expect(message).toContain('To: <user@example.com>');
    expect(message).toContain('Date: Mon, 26 Oct 2026 03:00:00 +0000');
    expect(message).toMatch(/Message-ID: <[0-9a-f-]{36}@example\.com>/);
    expect(message).toContain('Content-Type: text/plain; charset=utf-8');
    expect(bodyOf(message)).toBe('Your verification code is 000042. It expires in 10 minutes.');
  });

  it('encodes a non-ASCII display name and subject', () => {
    const message = buildMimeMessage(
      { ...config, fromName: '认证中心' },
      'user@example.com',
      { subject: '验证码', text: 'hi' },
      new Date('2026-10-26T03:00:00Z'),
    );
    expect(message).toMatch(/From: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?= <noreply@example\.com>/);
    expect(message).toMatch(/Subject: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=/);
  });

  it('formats RFC 2822 dates in UTC', () => {
    expect(rfc2822Date(new Date('2026-10-26T03:00:00Z'))).toBe('Mon, 26 Oct 2026 03:00:00 +0000');
  });
});

describe('weighted SMTP selection', () => {
  const a: SmtpConfig = { ...config, id: 1, weight: 1 };
  const b: SmtpConfig = { ...config, id: 2, weight: 3 };

  it('covers each bucket by cumulative weight', () => {
    expect(pickWeighted([a, b], 0)?.id).toBe(1);
    expect(pickWeighted([a, b], 0.24)?.id).toBe(1);
    expect(pickWeighted([a, b], 0.25)?.id).toBe(2);
    expect(pickWeighted([a, b], 0.99)?.id).toBe(2);
  });

  it('returns null when nothing is configured', () => {
    expect(pickWeighted([], 0.5)).toBeNull();
    expect(pickWeighted([{ ...a, weight: 0 }], 0.5)).toBeNull();
  });
});
