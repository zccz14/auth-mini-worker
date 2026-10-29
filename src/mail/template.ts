import type { MailContent } from './message';
import { OTP_SECONDS } from '../email/otp';

/**
 * What the two transactional mails say, and how much of it the administrator owns.
 *
 * A renamed instance must not keep mailing "auth-mini": subject and body are stored as templates
 * with `{brand}`, `{code}` and `{minutes}` placeholders and rendered at send time, so a brand
 * change reaches the very next mail without anyone editing a template. `''` means "no opinion" —
 * the built-in default stands, which keeps an untouched instance byte-identical to the legacy
 * wording, because the default brand is itself `auth-mini`.
 */
export interface MailTemplateOverrides {
  loginSubject: string;
  loginText: string;
  emailChangeSubject: string;
  emailChangeText: string;
}

/** The same four strings after the built-in defaults have filled the gaps. */
export interface MailTemplates {
  loginSubject: string;
  loginText: string;
  emailChangeSubject: string;
  emailChangeText: string;
}

/** What rendering needs: the stored overrides (possibly all `''`) and the brand in force today. */
export interface MailTemplateConfig {
  brandName: string;
  overrides: MailTemplateOverrides;
}

export interface MailTemplateReader {
  read(): Promise<MailTemplateConfig>;
}

/** The administrator route writes; the mail routes only read. */
export interface MailTemplateStore extends MailTemplateReader {
  write(overrides: MailTemplateOverrides): Promise<void>;
}

export const EMPTY_MAIL_TEMPLATES: MailTemplateOverrides = {
  loginSubject: '',
  loginText: '',
  emailChangeSubject: '',
  emailChangeText: '',
};

export const DEFAULT_LOGIN_SUBJECT = 'Your {brand} verification code';
export const DEFAULT_LOGIN_TEXT = 'Your verification code is {code}. It expires in {minutes} minutes.';
export const DEFAULT_EMAIL_CHANGE_SUBJECT = 'Confirm your {brand} email change';
export const DEFAULT_EMAIL_CHANGE_TEXT =
  'Your email change verification code is {code}. It expires in {minutes} minutes.';

/** The only placeholders a template may use; anything else is a typo, not a feature. */
export const MAIL_PLACEHOLDERS = ['brand', 'code', 'minutes'] as const;

export const MAIL_TEMPLATE_LIMITS = { subject: 200, text: 4_000 } as const;

export class MailTemplateError extends Error {}

export function resolveMailTemplates(overrides: MailTemplateOverrides): MailTemplates {
  return {
    loginSubject: overrides.loginSubject || DEFAULT_LOGIN_SUBJECT,
    loginText: overrides.loginText || DEFAULT_LOGIN_TEXT,
    emailChangeSubject: overrides.emailChangeSubject || DEFAULT_EMAIL_CHANGE_SUBJECT,
    emailChangeText: overrides.emailChangeText || DEFAULT_EMAIL_CHANGE_TEXT,
  };
}

/**
 * Substitution is single-pass: a `{brand}` that happens to contain braces cannot re-enter the
 * template, and an unknown placeholder is left visible instead of silently deleted. The write path
 * rejects those, so this is the belt to that pair of braces.
 */
function fill(template: string, values: Partial<Record<(typeof MAIL_PLACEHOLDERS)[number], string>>): string {
  return template.replace(/\{([^{}]*)\}/g, (match, name: string) => values[name as keyof typeof values] ?? match);
}

/** A subject is one header line; anything that could end it is not part of it. */
function renderSubject(template: string, values: Parameters<typeof fill>[1]): string {
  return fill(template, values).replace(/[\r\n]+/g, ' ').trim();
}

function otpMinutes(): string {
  return String(Math.round(OTP_SECONDS / 60));
}

function mailValues(config: MailTemplateConfig, code: string): Parameters<typeof fill>[1] {
  return { brand: config.brandName, code, minutes: otpMinutes() };
}

function checkTemplate(value: string, field: 'subject' | 'text', requireCode: boolean): string {
  const trimmed = value.trim();
  if (field === 'subject' && /[\r\n]/.test(trimmed)) throw new MailTemplateError('template_newline');
  if (trimmed.length > MAIL_TEMPLATE_LIMITS[field]) throw new MailTemplateError('template_too_long');
  for (const match of trimmed.matchAll(/\{([^{}]*)\}/g)) {
    if (!(MAIL_PLACEHOLDERS as readonly string[]).includes(match[1]!)) {
      throw new MailTemplateError('template_placeholder');
    }
  }
  // A body without the code mails a user something they cannot type back: refuse it at write time
  // rather than lock the instance out of email login one save later.
  if (requireCode && trimmed.length > 0 && !trimmed.includes('{code}')) {
    throw new MailTemplateError('template_missing_code');
  }
  return trimmed;
}

function readGroup(value: unknown, keys: readonly string[]): { subject: string; text: string } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new MailTemplateError('invalid_shape');
  const group = value as Record<string, unknown>;
  for (const key of Object.keys(group)) {
    if (!keys.includes(key)) throw new MailTemplateError('invalid_shape');
  }
  const subject = group['subject'];
  const text = group['text'];
  if (subject !== undefined && subject !== null && typeof subject !== 'string') throw new MailTemplateError('invalid_shape');
  if (text !== undefined && text !== null && typeof text !== 'string') throw new MailTemplateError('invalid_shape');
  return {
    subject: checkTemplate(typeof subject === 'string' ? subject : '', 'subject', false),
    text: checkTemplate(typeof text === 'string' ? text : '', 'text', true),
  };
}

/**
 * `{ login: { subject, text }, email_change: { subject, text } }` — the shape `PUT /admin/config`
 * accepts and `GET /admin/config` returns. An absent sub-field is "inherit the default"; unknown
 * groups or keys are rejected so a typo fails loudly instead of being dropped.
 */
export function parseMailTemplateOverrides(value: unknown): MailTemplateOverrides {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new MailTemplateError('invalid_shape');
  const groups = value as Record<string, unknown>;
  for (const key of Object.keys(groups)) {
    if (key !== 'login' && key !== 'email_change') throw new MailTemplateError('invalid_shape');
  }
  const login = readGroup(groups['login'], ['subject', 'text']);
  const emailChange = readGroup(groups['email_change'], ['subject', 'text']);
  return {
    loginSubject: login.subject,
    loginText: login.text,
    emailChangeSubject: emailChange.subject,
    emailChangeText: emailChange.text,
  };
}

export function loginOtpMail(code: string, config: MailTemplateConfig): MailContent {
  const templates = resolveMailTemplates(config.overrides);
  const values = mailValues(config, code);
  return {
    subject: renderSubject(templates.loginSubject, values),
    text: fill(templates.loginText, values),
  };
}

export function emailChangeOtpMail(code: string, config: MailTemplateConfig): MailContent {
  const templates = resolveMailTemplates(config.overrides);
  const values = mailValues(config, code);
  return {
    subject: renderSubject(templates.emailChangeSubject, values),
    text: fill(templates.emailChangeText, values),
  };
}
