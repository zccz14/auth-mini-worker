import { describe, expect, it } from 'vitest';
import { OTP_SECONDS } from '../src/email/otp';
import {
  DEFAULT_EMAIL_CHANGE_SUBJECT,
  DEFAULT_LOGIN_SUBJECT,
  MailTemplateError,
  emailChangeOtpMail,
  loginOtpMail,
  parseMailTemplateOverrides,
  resolveMailTemplates,
} from '../src/mail/template';
import { EMPTY_MAIL_TEMPLATES, type MailTemplateOverrides } from '../src/mail/template';

function overrides(patch: Partial<MailTemplateOverrides> = {}): MailTemplateOverrides {
  return { ...EMPTY_MAIL_TEMPLATES, ...patch };
}

describe('mail templates', () => {
  it('keeps the legacy wording for the legacy brand', () => {
    const config = { brandName: 'auth-mini', overrides: EMPTY_MAIL_TEMPLATES };

    expect(loginOtpMail('123456', config)).toEqual({
      subject: 'Your auth-mini verification code',
      text: 'Your verification code is 123456. It expires in 10 minutes.',
    });
    expect(emailChangeOtpMail('654321', config)).toEqual({
      subject: 'Confirm your auth-mini email change',
      text: 'Your email change verification code is 654321. It expires in 10 minutes.',
    });
  });

  it('renders the brand that is in force when the mail is sent', () => {
    const renamed = loginOtpMail('123456', { brandName: 'No Trade No Life', overrides: EMPTY_MAIL_TEMPLATES });
    expect(renamed.subject).toBe('Your No Trade No Life verification code');

    // A stored template that names no brand is not rewritten behind the administrator's back.
    const plain = loginOtpMail('123456', { brandName: 'No Trade No Life', overrides: overrides({ loginSubject: 'Sign-in code' }) });
    expect(plain.subject).toBe('Sign-in code');
    // The default body names no instance at all, so a rename does not silently rewrite it.
    expect(plain.text).toBe('Your verification code is 123456. It expires in 10 minutes.');

    const branded = loginOtpMail('123456', {
      brandName: 'No Trade No Life',
      overrides: overrides({ loginText: 'Welcome to {brand}. Your code is {code}.' }),
    });
    expect(branded.text).toBe('Welcome to No Trade No Life. Your code is 123456.');
  });

  it('takes {minutes} from the code lifetime, not from a literal', () => {
    const minutes = String(Math.round(OTP_SECONDS / 60));
    expect(loginOtpMail('123456', { brandName: 'auth-mini', overrides: EMPTY_MAIL_TEMPLATES }).text).toContain(
      `expires in ${minutes} minutes`,
    );

    const custom = emailChangeOtpMail('123456', {
      brandName: 'NTNL',
      overrides: overrides({ emailChangeText: '{brand}: {code} valid for {minutes} min' }),
    });
    expect(custom.text).toBe(`NTNL: 123456 valid for ${minutes} min`);
  });

  it('inherits field by field, so one blank box does not undo the other', () => {
    const mixed = resolveMailTemplates(overrides({ loginSubject: 'Sign-in code', loginText: 'Use {code}.' }));
    expect(mixed).toEqual({
      loginSubject: 'Sign-in code',
      loginText: 'Use {code}.',
      emailChangeSubject: DEFAULT_EMAIL_CHANGE_SUBJECT,
      emailChangeText: 'Your email change verification code is {code}. It expires in {minutes} minutes.',
    });
    expect(DEFAULT_LOGIN_SUBJECT).toBe('Your {brand} verification code');
  });

  it('never lets a stored template end the Subject header', () => {
    // The write path rejects this; rendering still flattens it, because a mail header is not a
    // place to discover that a check was skipped.
    const mail = loginOtpMail('123456', {
      brandName: 'auth-mini',
      overrides: overrides({ loginSubject: 'Hi\r\nBcc: someone@example.com' }),
    });
    expect(mail.subject).toBe('Hi Bcc: someone@example.com');
    expect(mail.subject).not.toContain('\n');
  });
});

describe('mail template validation', () => {
  const body = { subject: '', text: '{code}' };

  it('accepts the documented shape and keeps empty fields empty', () => {
    expect(parseMailTemplateOverrides({ login: body, email_change: { subject: '{brand}', text: '{brand} {code} {minutes}' } })).toEqual({
      loginSubject: '',
      loginText: '{code}',
      emailChangeSubject: '{brand}',
      emailChangeText: '{brand} {code} {minutes}',
    });
  });

  it('rejects a body without {code}, unknown placeholders and control characters', () => {
    expect(() => parseMailTemplateOverrides({ login: { subject: '', text: 'nothing to type' }, email_change: body })).toThrow(
      MailTemplateError,
    );
    expect(() => parseMailTemplateOverrides({ login: { subject: '', text: '{coode}' }, email_change: body })).toThrow(
      MailTemplateError,
    );
    expect(() => parseMailTemplateOverrides({ login: { subject: '{brand}\r\nX: y', text: '{code}' }, email_change: body })).toThrow(
      MailTemplateError,
    );
    // A multi-line body is the point of a body; only the subject is a single header line.
    expect(
      parseMailTemplateOverrides({ login: { subject: '', text: 'line one\n{code}\nline three' }, email_change: body }).loginText,
    ).toBe('line one\n{code}\nline three');
    expect(() => parseMailTemplateOverrides({ login: { subject: 'x'.repeat(201), text: '{code}' }, email_change: body })).toThrow(
      MailTemplateError,
    );
  });

  it('rejects shapes it does not recognise instead of dropping them', () => {
    expect(() => parseMailTemplateOverrides(null)).toThrow(MailTemplateError);
    expect(() => parseMailTemplateOverrides([])).toThrow(MailTemplateError);
    expect(() => parseMailTemplateOverrides({ login: body })).toThrow(MailTemplateError);
    expect(() => parseMailTemplateOverrides({ login: body, email_change: body, extra: body })).toThrow(MailTemplateError);
    expect(() => parseMailTemplateOverrides({ login: { ...body, extra: 'x' }, email_change: body })).toThrow(MailTemplateError);
  });
});
