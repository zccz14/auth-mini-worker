import { authenticateAccessToken } from '../auth';
import { sha256Hex } from '../crypto/tokens';
import { OTP_SECONDS, generateOtpCode, isEmailAddress, isSixDigitCode, normalizeEmail } from '../email/otp';
import { errorResponse, jsonResponse } from '../http/response';
import { StrictJsonError, parseStrictJsonObject, rejectUnknownKeys, requireString } from '../http/strict-json';
import { pickWeighted, type SmtpConfigStore } from '../mail/config';
import { emailChangeOtpMail, type MailSender } from '../mail/message';
import type { EmailChangeOtpStore } from '../stores';
import type { SessionDeps } from './session';

/**
 * The `/me/email/*` pair: changing the address of the account you are already signed in to.
 *
 * Login (`/email/*`) proves an address; this proves a *new* address for an existing user. The two
 * share the code rules and the SMTP pick, but not the table: `email_change_otps` is keyed by user
 * and holds at most one pending address, so a retry replaces the previous code.
 */
export interface EmailChangeDeps extends SessionDeps {
  emailChangeStore: EmailChangeOtpStore;
  smtpStore: SmtpConfigStore;
  sendMail: MailSender;
  /** Injectable so tests can pin the weighted SMTP draw. */
  draw?: number;
}

/** POST /me/email/start — send a code to the address the caller wants to move to. */
export async function handleEmailChangeStart(request: Request, deps: EmailChangeDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');

  let email: string;
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['email']);
    email = normalizeEmail(requireString(body, 'email'));
  } catch (error) {
    if (error instanceof StrictJsonError) return errorResponse(400, 'invalid_request');
    throw error;
  }
  if (!isEmailAddress(email)) return errorResponse(400, 'invalid_request');

  // Checked before the SMTP pick, like the legacy handler: an address that is already taken is a
  // fact about the request, not about delivery.
  if (await deps.emailChangeStore.emailInUse(email)) return errorResponse(409, 'email_already_in_use');

  const config = pickWeighted(await deps.smtpStore.listActive(), deps.draw ?? Math.random());
  if (!config) return errorResponse(503, 'smtp_not_configured');

  const code = generateOtpCode();
  const expiresAt = new Date(deps.now.getTime() + OTP_SECONDS * 1000).toISOString();
  await deps.emailChangeStore.upsert(auth.userId, email, await sha256Hex(code), expiresAt);

  try {
    await deps.sendMail(config, email, emailChangeOtpMail(code));
  } catch {
    // Never leave a code behind that the user cannot possibly have received.
    await deps.emailChangeStore.invalidate(auth.userId);
    return errorResponse(503, 'smtp_temporarily_unavailable');
  }

  return jsonResponse({ ok: true });
}

/**
 * POST /me/email/verify — spend the code and move the address.
 *
 * `401 invalid_email_change_otp` covers expired, consumed, wrong-address and wrong-code alike: the
 * caller learns nothing about which one it was.
 */
export async function handleEmailChangeVerify(request: Request, deps: EmailChangeDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');

  let email: string;
  let code: string;
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['email', 'code']);
    email = normalizeEmail(requireString(body, 'email'));
    code = requireString(body, 'code');
  } catch (error) {
    if (error instanceof StrictJsonError) return errorResponse(400, 'invalid_request');
    throw error;
  }
  if (!isEmailAddress(email) || !isSixDigitCode(code)) return errorResponse(400, 'invalid_request');

  const now = deps.now.toISOString();
  if (!(await deps.emailChangeStore.consume(auth.userId, email, await sha256Hex(code), now))) {
    return errorResponse(401, 'invalid_email_change_otp');
  }
  if (!(await deps.emailChangeStore.assignEmail(auth.userId, email, now))) {
    return errorResponse(409, 'email_already_in_use');
  }

  return jsonResponse({ ok: true });
}
