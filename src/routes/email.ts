import { AudienceError, resolveAudiences } from '../audience';
import { sha256Hex } from '../crypto/tokens';
import type { EmailOtpStore, SessionStore, UserStore } from '../stores';
import { OTP_SECONDS, generateOtpCode, isEmailAddress, isSixDigitCode, normalizeEmail } from '../email/otp';
import { StrictJsonError, optionalString, parseStrictJsonObject, rejectUnknownKeys, requireString } from '../http/strict-json';
import { errorResponse, jsonResponse } from '../http/response';
import type { SigningKeyStore } from '../jwks';
import type { MailContent } from '../mail/message';
import type { SmtpConfig, SmtpConfigStore } from '../mail/config';
import { pickWeighted } from '../mail/config';
import { mintSession, tokenJson } from '../session';

export interface EmailDeps {
  issuer: string;
  otpStore: EmailOtpStore;
  userStore: UserStore;
  sessionStore: SessionStore;
  keyStore: SigningKeyStore;
  smtpStore: SmtpConfigStore;
  sendMail: (config: SmtpConfig, to: string, content: MailContent) => Promise<void>;
  now: Date;
  clientIp: string | null;
  userAgent: string | null;
  /** Injectable so tests can pin the weighted draw. */
  draw?: number;
}

function badRequest(): Response {
  return errorResponse(400, 'invalid_request');
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  return parseStrictJsonObject(await request.text());
}

/** POST /email/start — issue a code, store its hash, deliver it. */
export async function handleEmailStart(request: Request, deps: EmailDeps): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = await readJson(request);
    rejectUnknownKeys(body, ['email']);
  } catch (error) {
    if (error instanceof StrictJsonError) return badRequest();
    throw error;
  }

  let email: string;
  try {
    email = normalizeEmail(requireString(body, 'email'));
  } catch {
    return badRequest();
  }
  if (!isEmailAddress(email)) return badRequest();

  const config = pickWeighted(await deps.smtpStore.listActive(), deps.draw ?? Math.random());
  if (!config) return errorResponse(503, 'smtp_not_configured');

  const code = generateOtpCode();
  const expiresAt = new Date(deps.now.getTime() + OTP_SECONDS * 1000).toISOString();
  await deps.otpStore.upsert(email, await sha256Hex(code), expiresAt);

  try {
    await deps.sendMail(config, email, {
      subject: 'Your auth-mini verification code',
      text: `Your verification code is ${code}. It expires in 10 minutes.`,
    });
  } catch {
    // Never leave a code behind that the user cannot possibly have received.
    await deps.otpStore.invalidate(email);
    return errorResponse(503, 'smtp_temporarily_unavailable');
  }

  return jsonResponse({ ok: true });
}

function readAudienceFields(body: Record<string, unknown>): { redirectUri?: string; aud?: string; audiences?: string[] } {
  const redirectUri = optionalString(body, 'redirect_uri');
  const aud = optionalString(body, 'aud');
  const rawAudiences = body['audiences'];
  let audiences: string[] | undefined;
  if (rawAudiences !== undefined) {
    if (!Array.isArray(rawAudiences) || rawAudiences.length === 0) throw new StrictJsonError('invalid_field');
    if (!rawAudiences.every((value) => typeof value === 'string')) throw new StrictJsonError('invalid_field');
    audiences = rawAudiences as string[];
  }
  return {
    ...(redirectUri === null ? {} : { redirectUri }),
    ...(aud === null ? {} : { aud }),
    ...(audiences === undefined ? {} : { audiences }),
  };
}

/** POST /email/verify — consume the code atomically, then mint a session. */
export async function handleEmailVerify(request: Request, deps: EmailDeps): Promise<Response> {
  let body: Record<string, unknown>;
  let email: string;
  let code: string;
  let audienceFields: { redirectUri?: string; aud?: string; audiences?: string[] };
  try {
    body = await readJson(request);
    rejectUnknownKeys(body, ['email', 'code', 'redirect_uri', 'aud', 'audiences']);
    email = normalizeEmail(requireString(body, 'email'));
    code = requireString(body, 'code');
    audienceFields = readAudienceFields(body);
  } catch (error) {
    if (error instanceof StrictJsonError) return badRequest();
    throw error;
  }
  if (!isEmailAddress(email) || !isSixDigitCode(code)) return badRequest();

  let audiences: string[];
  try {
    audiences = resolveAudiences(deps.issuer, audienceFields);
  } catch (error) {
    if (error instanceof AudienceError) return badRequest();
    throw error;
  }

  const now = deps.now.toISOString();
  const consumed = await deps.otpStore.consume(email, await sha256Hex(code), now);
  if (!consumed) return errorResponse(401, 'invalid_email_otp');

  const userId = await deps.userStore.ensureByEmail(email, now);
  const pair = await mintSession({
    keyStore: deps.keyStore,
    sessionStore: deps.sessionStore,
    issuer: deps.issuer,
    userId,
    authMethod: 'email_otp',
    sourceAuthMethod: null,
    audiences,
    ip: deps.clientIp,
    userAgent: deps.userAgent,
    isAdmin: await deps.userStore.isAdmin(userId),
    now: deps.now,
  });

  return jsonResponse(tokenJson(pair));
}
