import type { AuthDeps } from '../auth';
import { activeSessionJson, authenticateAccessToken, hasSelfAudience } from '../auth';
import { ACCESS_TOKEN_SECONDS, REFRESH_TOKEN_SECONDS, randomHex, sha256Hex } from '../crypto/tokens';
import { errorResponse, jsonResponse } from '../http/response';
import { StrictJsonError, parseStrictJsonObject, rejectUnknownKeys, requireString } from '../http/strict-json';
import { currentSigningKey } from '../jwks';
import { buildAccessTokenClaims, signAccessToken } from '../jwt';
import type { CredentialStore, UserStore } from '../stores';
import { tokenJson } from '../session';

export interface SessionDeps extends AuthDeps {
  userStore: UserStore;
  credentialStore: CredentialStore;
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  return parseStrictJsonObject(await request.text());
}

const UUID_LIKE = 36;

/** POST /session/refresh — rotate the refresh token, mint a fresh access token. */
export async function handleSessionRefresh(request: Request, deps: SessionDeps): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = await readJson(request);
    rejectUnknownKeys(body, ['session_id', 'refresh_token']);
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  let sessionId: string;
  let refreshToken: string;
  try {
    sessionId = requireString(body, 'session_id');
    refreshToken = requireString(body, 'refresh_token');
  } catch {
    return errorResponse(400, 'invalid_request');
  }
  if (sessionId.length !== UUID_LIKE) return errorResponse(400, 'invalid_request');

  const now = deps.now.toISOString();
  const session = await deps.sessionStore.find(sessionId);
  if (!session || session.expiresAt <= now) return errorResponse(401, 'session_invalidated');

  const presentedHash = await sha256Hex(refreshToken);
  if (session.refreshTokenHash !== presentedHash) return errorResponse(401, 'session_superseded');

  const nextRefreshToken = randomHex(32);
  const nextHash = await sha256Hex(nextRefreshToken);
  const nextExpiresAt = new Date(deps.now.getTime() + REFRESH_TOKEN_SECONDS * 1000).toISOString();

  const rotated = await deps.sessionStore.rotate(sessionId, presentedHash, nextHash, nextExpiresAt, now);
  if (!rotated) return errorResponse(401, 'session_superseded');

  const key = await currentSigningKey(deps.keyStore);
  const authenticationMethods = session.sourceAuthMethod
    ? [session.authMethod, session.sourceAuthMethod]
    : [session.authMethod];
  const claims = buildAccessTokenClaims({
    userId: session.userId,
    sessionId: session.id,
    issuer: deps.issuer,
    audiences: session.audiences,
    authenticationMethods,
    authAdmin: await deps.userStore.isAdmin(session.userId),
    nowSeconds: Math.floor(deps.now.getTime() / 1000),
    lifetimeSeconds: ACCESS_TOKEN_SECONDS,
  });
  const accessToken = await signAccessToken({ kid: key.kid, privateJwk: key.privateJwk }, claims);

  return jsonResponse(tokenJson({ sessionId: session.id, accessToken, refreshToken: nextRefreshToken }));
}

/** POST /session/logout — expire the caller's own session. */
export async function handleSessionLogout(request: Request, deps: SessionDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');

  await deps.sessionStore.expire(auth.sessionId, deps.now.toISOString());
  return jsonResponse({ ok: true });
}

/** GET /me — self-audience profile. */
export async function handleMe(request: Request, deps: SessionDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');
  if (!hasSelfAudience(auth, deps.issuer)) return errorResponse(401, 'invalid_access_token');

  const now = deps.now.toISOString();
  const [email, webauthn, ed25519, sessions] = await Promise.all([
    deps.userStore.findEmail(auth.userId),
    deps.credentialStore.listWebauthn(auth.userId),
    deps.credentialStore.listEd25519(auth.userId),
    deps.sessionStore.listActive(auth.userId, now),
  ]);

  return jsonResponse({
    user_id: auth.userId,
    email,
    auth_admin: await deps.userStore.isAdmin(auth.userId),
    webauthn_credentials: webauthn,
    ed25519_credentials: ed25519,
    active_sessions: sessions.map(activeSessionJson),
  });
}

/** GET /time — clock snapshot for the SDKs' skew calibration. */
export function handleTime(now: Date): Response {
  return jsonResponse(
    { now: Math.floor(now.getTime() / 1000), now_ms: now.getTime(), iso: now.toISOString() },
    200,
    { 'cache-control': 'no-store' },
  );
}

export { StrictJsonError };
