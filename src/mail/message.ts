import { uuidv4 } from '../crypto/tokens';
import type { SmtpConfig } from './config';

export interface MailContent {
  subject: string;
  text: string;
}

function encodeHeaderValue(value: string): string {
  // RFC 2047 only when needed, otherwise leave the readable form alone.
  if (/^[\x20-\x7e]*$/.test(value)) return value;
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `=?UTF-8?B?${btoa(binary)}?=`;
}

function formatAddress(email: string, name: string): string {
  if (name.trim().length === 0) return `<${email}>`;
  return `${encodeHeaderValue(name)} <${email}>`;
}

function wrapBase64(value: string): string {
  return (value.match(/.{1,76}/g) ?? []).join('\r\n');
}

function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** RFC 2822 date, e.g. `Sun, 26 Oct 2026 03:55:32 +0000`. */
export function rfc2822Date(when: Date): string {
  return when.toUTCString().replace('GMT', '+0000');
}

/**
 * Builds a self-contained text/plain message. Body is base64 so dot-stuffing and line
 * length never depend on the SMTP server's mood.
 */
export function buildMimeMessage(config: SmtpConfig, to: string, content: MailContent, when: Date): string {
  const domain = config.fromEmail.split('@')[1] ?? 'localhost';
  const headers = [
    `From: ${formatAddress(config.fromEmail, config.fromName)}`,
    `To: <${to}>`,
    `Subject: ${encodeHeaderValue(content.subject)}`,
    `Date: ${rfc2822Date(when)}`,
    `Message-ID: <${uuidv4()}@${domain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
  ];
  return `${headers.join('\r\n')}\r\n\r\n${wrapBase64(toBase64(content.text))}`;
}

export function otpMail(code: string): MailContent {
  return {
    subject: 'Your auth-mini verification code',
    text: `Your verification code is ${code}. It expires in 10 minutes.`,
  };
}

export function emailChangeOtpMail(code: string): MailContent {
  return {
    subject: 'Confirm your auth-mini email change',
    text: `Your email change verification code is ${code}. It expires in 10 minutes.`,
  };
}
