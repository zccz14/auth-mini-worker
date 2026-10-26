import { AudienceError, isLoopbackRedirect, issuerAudience, resolveAudiences } from '../audience';
import { authenticateAccessToken } from '../auth';
import { sha256Hex, randomHex, uuidv4 } from '../crypto/tokens';
import { errorResponse, jsonResponse } from '../http/response';
import { StrictJsonError, optionalString, parseStrictJsonObject, rejectUnknownKeys, requireString } from '../http/strict-json';
import { mintSession, tokenJson } from '../session';
import type { RemoteLoginRow, RemoteLoginStore } from '../stores';
import type { SessionDeps } from './session';

export const REMOTE_LOGIN_SECONDS = 300;

export interface RemoteLoginDeps extends SessionDeps {
  remoteLoginStore: RemoteLoginStore;
  clientIp: string | null;
  userAgent: string | null;
}

function readAudienceFields(body: Record<string, unknown>): { redirectUri?: string; aud?: string; audiences?: string[] } {
  const redirectUri = optionalString(body, 'redirect_uri');
  const aud = optionalString(body, 'aud');
  const raw = body['audiences'];
  let audiences: string[] | undefined;
  if (raw !== undefined) {
    if (!Array.isArray(raw) || raw.length === 0 || !raw.every((value) => typeof value === 'string')) {
      throw new StrictJsonError('invalid_field');
    }
    audiences = raw as string[];
  }
  return {
    ...(redirectUri === null ? {} : { redirectUri }),
    ...(aud === null ? {} : { aud }),
    ...(audiences === undefined ? {} : { audiences }),
  };
}

function summaryJson(row: RemoteLoginRow): Record<string, unknown> {
  return {
    request_id: row.requestId,
    redirect_uri: row.redirectUri,
    audiences: row.audiences,
    expires_at: row.expiresAt,
    created_at: row.createdAt,
  };
}

const UNAVAILABLE = () => errorResponse(401, 'remote_login_unavailable');

/** POST /remote-login/start — the device asks; nobody is authenticated yet. */
export async function handleRemoteLoginStart(request: Request, deps: RemoteLoginDeps): Promise<Response> {
  let fields: { redirectUri?: string; aud?: string; audiences?: string[] };
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['redirect_uri', 'aud', 'audiences']);
    fields = readAudienceFields(body);
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  let audiences: string[];
  try {
    audiences = resolveAudiences(deps.issuer, fields);
  } catch (error) {
    if (error instanceof AudienceError) return errorResponse(400, 'invalid_request');
    throw error;
  }

  const requestId = uuidv4();
  // 32 bytes as 64 hex characters, and a 4-byte code shown to the human, uppercased.
  const exchangeCode = randomHex(32);
  const confirmationCode = randomHex(4).toUpperCase();
  const expiresAt = new Date(deps.now.getTime() + REMOTE_LOGIN_SECONDS * 1000).toISOString();

  await deps.remoteLoginStore.create({
    requestId,
    exchangeCodeHash: await sha256Hex(exchangeCode),
    confirmationCodeHash: await sha256Hex(confirmationCode),
    redirectUri: fields.redirectUri ?? null,
    audiences,
    expiresAt,
    now: deps.now.toISOString(),
  });

  return jsonResponse({ request_id: requestId, exchange_code: exchangeCode, confirmation_code: confirmationCode, expires_at: expiresAt });
}

/** GET /remote-login/pending — requests this signed-in user has claimed and not yet decided. */
export async function handleRemoteLoginPending(request: Request, deps: RemoteLoginDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');

  const now = deps.now.toISOString();
  await deps.remoteLoginStore.expireStale(now);
  const rows = await deps.remoteLoginStore.listPending(auth.userId, now);
  return jsonResponse({ requests: rows.map(summaryJson) });
}

/** POST /remote-login/claim — bind a pending request to the approving user via its short code. */
export async function handleRemoteLoginClaim(request: Request, deps: RemoteLoginDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');

  let confirmationCode: string;
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['confirmation_code']);
    const raw = requireString(body, 'confirmation_code');
    if (!/^[0-9a-fA-F]{8}$/.test(raw)) return errorResponse(400, 'invalid_request');
    confirmationCode = raw.toUpperCase();
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  const now = deps.now.toISOString();
  const codeHash = await sha256Hex(confirmationCode);
  const requestId = await deps.remoteLoginStore.findIdByConfirmationCode(codeHash, now);
  if (!requestId) return UNAVAILABLE();

  if (!(await deps.remoteLoginStore.claim(requestId, auth.userId, codeHash, now))) return UNAVAILABLE();

  const summary = await deps.remoteLoginStore.summary(requestId, auth.userId);
  if (!summary) return UNAVAILABLE();
  return jsonResponse(summaryJson(summary));
}

async function decide(request: Request, deps: RemoteLoginDeps, requestId: string, status: 'approved' | 'denied'): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');

  if (requestId.length !== 36) return errorResponse(400, 'invalid_request');
  if (!(await deps.remoteLoginStore.decide(requestId, auth.userId, status, deps.now.toISOString()))) return UNAVAILABLE();
  return jsonResponse({ ok: true });
}

/** POST /remote-login/{id}/approve */
export async function handleRemoteLoginApprove(request: Request, deps: RemoteLoginDeps, requestId: string): Promise<Response> {
  return decide(request, deps, requestId, 'approved');
}

/** POST /remote-login/{id}/deny */
export async function handleRemoteLoginDeny(request: Request, deps: RemoteLoginDeps, requestId: string): Promise<Response> {
  return decide(request, deps, requestId, 'denied');
}

/** POST /remote-login/{id}/exchange — the waiting device trades its code for tokens. */
export async function handleRemoteLoginExchange(request: Request, deps: RemoteLoginDeps, requestId: string): Promise<Response> {
  let bodyRequestId: string;
  let exchangeCode: string;
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['request_id', 'exchange_code']);
    bodyRequestId = requireString(body, 'request_id');
    exchangeCode = requireString(body, 'exchange_code');
  } catch {
    return errorResponse(400, 'invalid_request');
  }
  if (bodyRequestId.length !== 36 || requestId.length !== 36 || bodyRequestId !== requestId) return errorResponse(400, 'invalid_request');
  if (!/^[0-9a-fA-F]{64}$/.test(exchangeCode)) return errorResponse(400, 'invalid_request');

  const now = deps.now.toISOString();
  const codeHash = await sha256Hex(exchangeCode);
  const approved = await deps.remoteLoginStore.findApproved(requestId, codeHash, now);
  if (!approved) return UNAVAILABLE();

  // Spend the request before minting: a replay must lose the race, not create a second session.
  if (!(await deps.remoteLoginStore.consume(requestId, codeHash, now))) return UNAVAILABLE();

  const pair = await mintSession({
    keyStore: deps.keyStore,
    sessionStore: deps.sessionStore,
    issuer: deps.issuer,
    userId: approved.userId,
    authMethod: 'agent_approval',
    sourceAuthMethod: null,
    audiences: approved.audiences,
    ip: deps.clientIp,
    userAgent: deps.userAgent,
    isAdmin: await deps.userStore.isAdmin(approved.userId),
    now: deps.now,
  });

  return jsonResponse(tokenJson(pair));
}

/** POST /session/authorize — delegate a session to a downstream app from an existing one. */
export async function handleSessionAuthorize(request: Request, deps: SessionDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');

  let fields: { redirectUri?: string; aud?: string; audiences?: string[] };
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['redirect_uri', 'aud', 'audiences']);
    fields = readAudienceFields(body);
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  let audiences: string[];
  try {
    audiences = resolveAudiences(deps.issuer, fields);
  } catch (error) {
    if (error instanceof AudienceError) return errorResponse(400, 'invalid_request');
    throw error;
  }

  // Only a loopback target may hold main-site tokens: a remote site must not obtain them by
  // delegating through /session/authorize.
  if (audiences.includes(issuerAudience(deps.issuer)) && !isLoopbackRedirect(fields.redirectUri)) {
    return errorResponse(400, 'invalid_request');
  }

  const pair = await mintSession({
    keyStore: deps.keyStore,
    sessionStore: deps.sessionStore,
    issuer: deps.issuer,
    userId: auth.userId,
    authMethod: 'sso',
    sourceAuthMethod: auth.authMethod,
    audiences,
    ip: null,
    userAgent: null,
    isAdmin: await deps.userStore.isAdmin(auth.userId),
    now: deps.now,
  });

  return jsonResponse(tokenJson(pair));
}
