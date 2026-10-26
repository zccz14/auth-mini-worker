import type { AuthContext } from '../auth';
import { authenticateAccessToken } from '../auth';
import { AudienceError, resolveAudiences } from '../audience';
import { ED25519_CHALLENGE_SECONDS, decodePublicKey, newChallenge, verifyChallengeSignature } from '../ed25519';
import { errorResponse, jsonResponse } from '../http/response';
import { StrictJsonError, optionalString, parseStrictJsonObject, rejectUnknownKeys, requireString } from '../http/strict-json';
import { mintSession, tokenJson } from '../session';
import type { Ed25519CredentialRow, UserStore } from '../stores';
import type { SessionDeps } from './session';

export interface Ed25519Deps extends SessionDeps {
  ed25519Store: import('../stores').Ed25519Store;
  clientIp: string | null;
  userAgent: string | null;
}

/** Legacy `require_passkey_management_auth`: only a strong sign-in may manage device keys. */
export function mayManageCredentials(auth: AuthContext): boolean {
  return auth.authMethod === 'email_otp' || auth.authMethod === 'webauthn';
}

export function credentialJson(row: Ed25519CredentialRow): Record<string, unknown> {
  return {
    id: row.id,
    name: row.name,
    public_key: row.publicKey,
    last_used_at: row.lastUsedAt,
    created_at: row.createdAt,
  };
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  return parseStrictJsonObject(await request.text());
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

/** POST /ed25519/start — hand the device a challenge bound to its public key. */
export async function handleEd25519Start(request: Request, deps: Ed25519Deps): Promise<Response> {
  let publicKey: string;
  try {
    const body = await readJson(request);
    rejectUnknownKeys(body, ['public_key']);
    publicKey = requireString(body, 'public_key');
  } catch {
    return errorResponse(400, 'invalid_request');
  }
  if (!decodePublicKey(publicKey)) return errorResponse(400, 'invalid_request');

  const credentialIds = await deps.ed25519Store.credentialIdsByPublicKey(publicKey);
  if (credentialIds.length !== 1) return errorResponse(400, 'invalid_ed25519_authentication');

  const requestId = crypto.randomUUID();
  const challenge = newChallenge();
  const now = deps.now.toISOString();
  const expiresAt = new Date(deps.now.getTime() + ED25519_CHALLENGE_SECONDS * 1000).toISOString();
  await deps.ed25519Store.createChallenge(requestId, credentialIds[0]!, challenge, expiresAt, now);

  return jsonResponse({ request_id: requestId, challenge });
}

/** POST /ed25519/verify — check the signature over the challenge, then mint a session. */
export async function handleEd25519Verify(request: Request, deps: Ed25519Deps): Promise<Response> {
  let body: Record<string, unknown>;
  let requestId: string;
  let signature: string;
  let audienceFields: { redirectUri?: string; aud?: string; audiences?: string[] };
  try {
    body = await readJson(request);
    rejectUnknownKeys(body, ['request_id', 'signature', 'redirect_uri', 'aud', 'audiences']);
    requestId = requireString(body, 'request_id');
    signature = requireString(body, 'signature');
    audienceFields = readAudienceFields(body);
  } catch {
    return errorResponse(400, 'invalid_request');
  }
  if (requestId.length !== 36) return errorResponse(400, 'invalid_request');

  let audiences: string[];
  try {
    audiences = resolveAudiences(deps.issuer, audienceFields);
  } catch (error) {
    if (error instanceof AudienceError) return errorResponse(400, 'invalid_request');
    throw error;
  }

  const now = deps.now.toISOString();
  const challenge = await deps.ed25519Store.findChallenge(requestId);
  if (!challenge || challenge.consumedAt !== null || challenge.expiresAt <= now) {
    return errorResponse(400, 'invalid_ed25519_authentication');
  }

  const credential = await deps.ed25519Store.credentialById(challenge.credentialId);
  if (!credential) return errorResponse(400, 'invalid_ed25519_authentication');

  if (!(await verifyChallengeSignature(challenge.challenge, credential.publicKey, signature))) {
    return errorResponse(400, 'invalid_ed25519_authentication');
  }

  // The signature is good; only now is the challenge spent. Two concurrent verifications of the
  // same challenge cannot both pass, which is what stops replay.
  if (!(await deps.ed25519Store.consumeChallenge(requestId, now))) {
    return errorResponse(400, 'invalid_ed25519_authentication');
  }
  await deps.ed25519Store.touchLastUsed(credential.id, now);

  const pair = await mintSession({
    keyStore: deps.keyStore,
    sessionStore: deps.sessionStore,
    issuer: deps.issuer,
    userId: credential.userId,
    authMethod: 'ed25519',
    sourceAuthMethod: null,
    audiences,
    ip: deps.clientIp,
    userAgent: deps.userAgent,
    isAdmin: await deps.userStore.isAdmin(credential.userId),
    now: deps.now,
  });

  return jsonResponse(tokenJson(pair));
}

async function requireManager(request: Request, deps: Ed25519Deps): Promise<Response | AuthContext> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');
  if (!mayManageCredentials(auth)) return errorResponse(403, 'insufficient_authentication_method');
  return auth;
}

/** GET /ed25519/credentials */
export async function handleEd25519CredentialsList(request: Request, deps: Ed25519Deps): Promise<Response> {
  const auth = await requireManager(request, deps);
  if (auth instanceof Response) return auth;
  const rows = await deps.ed25519Store.listByUser(auth.userId);
  return jsonResponse(rows.map(credentialJson));
}

/** POST /ed25519/credentials */
export async function handleEd25519CredentialCreate(request: Request, deps: Ed25519Deps): Promise<Response> {
  let name: string;
  let publicKey: string;
  try {
    const body = await readJson(request);
    rejectUnknownKeys(body, ['name', 'public_key']);
    name = requireString(body, 'name');
    publicKey = requireString(body, 'public_key');
  } catch {
    return errorResponse(400, 'invalid_ed25519_credential');
  }
  if (name.length === 0 || !decodePublicKey(publicKey)) return errorResponse(400, 'invalid_ed25519_credential');

  const auth = await requireManager(request, deps);
  if (auth instanceof Response) return auth;

  const created = await deps.ed25519Store.create(auth.userId, name, publicKey, deps.now.toISOString());
  if (!created) return errorResponse(400, 'invalid_ed25519_credential');
  return jsonResponse(credentialJson(created));
}

/** PATCH /ed25519/credentials/{id} */
export async function handleEd25519CredentialUpdate(request: Request, deps: Ed25519Deps, credentialId: string): Promise<Response> {
  let name: string;
  try {
    const body = await readJson(request);
    rejectUnknownKeys(body, ['name']);
    name = requireString(body, 'name');
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  const auth = await requireManager(request, deps);
  if (auth instanceof Response) return auth;

  const updated = await deps.ed25519Store.updateName(credentialId, auth.userId, name);
  if (!updated) return errorResponse(404, 'credential_not_found');
  return jsonResponse(credentialJson(updated));
}

/** DELETE /ed25519/credentials/{id} */
export async function handleEd25519CredentialDelete(request: Request, deps: Ed25519Deps, credentialId: string): Promise<Response> {
  const auth = await requireManager(request, deps);
  if (auth instanceof Response) return auth;

  const removed = await deps.ed25519Store.remove(credentialId, auth.userId);
  if (!removed) return errorResponse(404, 'credential_not_found');
  return jsonResponse({ ok: true });
}

export type { UserStore };
