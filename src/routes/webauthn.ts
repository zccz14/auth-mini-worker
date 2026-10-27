import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import type { AuthContext } from '../auth';
import { authenticateAccessToken } from '../auth';
import { AudienceError, resolveAudiences } from '../audience';
import { b64urlEncode } from '../crypto/b64url';
import { uuidv4 } from '../crypto/tokens';
import { errorResponse, jsonResponse } from '../http/response';
import { StrictJsonError, optionalString, parseStrictJsonObject, rejectUnknownKeys } from '../http/strict-json';
import { mintSession, tokenJson } from '../session';
import type { AdminStore, UserStore, WebauthnStore } from '../stores';
import type { RegistrationOutcome } from '../webauthn';
import {
  WEBAUTHN_CHALLENGE_SECONDS,
  authenticationOptions,
  newChallenge,
  parsePasskey,
  registrationOptions,
  resolveWebauthnConfig,
  serializePasskey,
  verifyAssertionCeremony,
  verifyRegistrationCeremony,
  webauthnUserHandleText,
} from '../webauthn';
import { mayManageCredentials } from './ed25519';
import type { SessionDeps } from './session';

export interface WebauthnDeps extends SessionDeps {
  userStore: UserStore;
  webauthnStore: WebauthnStore;
  adminStore: AdminStore;
  clientIp: string | null;
  userAgent: string | null;
}

export const REGISTER_INVALID = 'invalid_webauthn_registration';
const AUTHENTICATE_INVALID = 'invalid_webauthn_authentication';

export function isUuid(value: string): boolean {
  if (value.length !== 36) return false;
  for (let index = 0; index < 36; index += 1) {
    const char = value[index]!;
    if (index === 8 || index === 13 || index === 18 || index === 23) {
      if (char !== '-') return false;
    } else if (!/[0-9a-fA-F]/.test(char)) {
      return false;
    }
  }
  return true;
}

function asObject(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function transportsField(value: unknown): string[] | undefined | null {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) return null;
  if (!value.every((entry) => typeof entry === 'string' && entry.length > 0)) return null;
  return value as string[];
}

/**
 * `#[serde(deny_unknown_fields)]` reaches into the nested credential objects too, so every level
 * gets checked here. A browser that grows a new field fails closed instead of being half-read.
 */
export function parseRegistrationCredential(raw: unknown): RegistrationResponseJSON | null {
  const credential = asObject(raw);
  if (credential === null) return null;
  try {
    rejectUnknownKeys(credential, ['id', 'rawId', 'type', 'authenticatorAttachment', 'clientExtensionResults', 'response']);
  } catch {
    return null;
  }

  const id = nonEmptyString(credential['id']);
  const rawId = nonEmptyString(credential['rawId']);
  if (id === null || rawId === null || id !== rawId) return null;
  if (credential['type'] !== 'public-key') return null;

  const attachment = credential['authenticatorAttachment'];
  if (attachment !== undefined && typeof attachment !== 'string') return null;

  const extensionResults = credential['clientExtensionResults'];
  if (extensionResults !== undefined && asObject(extensionResults) === null) return null;

  const response = asObject(credential['response']);
  if (response === null) return null;
  try {
    rejectUnknownKeys(response, ['clientDataJSON', 'attestationObject', 'transports']);
  } catch {
    return null;
  }
  const clientDataJSON = nonEmptyString(response['clientDataJSON']);
  const attestationObject = nonEmptyString(response['attestationObject']);
  if (clientDataJSON === null || attestationObject === null) return null;
  const transports = transportsField(response['transports']);
  if (transports === null) return null;

  return {
    id,
    rawId,
    type: 'public-key',
    ...(typeof attachment === 'string' ? { authenticatorAttachment: attachment as never } : {}),
    clientExtensionResults: (extensionResults ?? {}) as never,
    response: {
      clientDataJSON,
      attestationObject,
      ...(transports === undefined ? {} : { transports: transports as never }),
    },
  };
}

function parseAuthenticationCredential(raw: unknown): AuthenticationResponseJSON | null {
  const credential = asObject(raw);
  if (credential === null) return null;
  // The OpenAPI schema allows `authenticatorAttachment` here even though the Rust struct did not;
  // we follow the published contract and ignore the value, which carries no trust.
  try {
    rejectUnknownKeys(credential, ['id', 'rawId', 'type', 'authenticatorAttachment', 'clientExtensionResults', 'response']);
  } catch {
    return null;
  }

  const id = nonEmptyString(credential['id']);
  const rawId = nonEmptyString(credential['rawId']);
  if (id === null || rawId === null || id !== rawId) return null;
  if (credential['type'] !== 'public-key') return null;

  const attachment = credential['authenticatorAttachment'];
  if (attachment !== undefined && typeof attachment !== 'string') return null;

  const extensionResults = credential['clientExtensionResults'];
  if (extensionResults !== undefined && asObject(extensionResults) === null) return null;

  const response = asObject(credential['response']);
  if (response === null) return null;
  try {
    rejectUnknownKeys(response, ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']);
  } catch {
    return null;
  }
  const clientDataJSON = nonEmptyString(response['clientDataJSON']);
  const authenticatorData = nonEmptyString(response['authenticatorData']);
  const signature = nonEmptyString(response['signature']);
  if (clientDataJSON === null || authenticatorData === null || signature === null) return null;

  const userHandle = response['userHandle'];
  if (userHandle !== undefined && userHandle !== null && nonEmptyString(userHandle) === null) return null;

  return {
    id,
    rawId,
    type: 'public-key',
    ...(typeof attachment === 'string' ? { authenticatorAttachment: attachment as never } : {}),
    clientExtensionResults: (extensionResults ?? {}) as never,
    response: {
      clientDataJSON,
      authenticatorData,
      signature,
      ...(userHandle === undefined || userHandle === null ? {} : { userHandle: userHandle as string }),
    },
  };
}

/** `credProps.rk === false` means the authenticator told us the credential is not discoverable. */
export function reportsNonDiscoverable(extensionResults: unknown): boolean {
  const props = asObject(asObject(extensionResults)?.['credProps']);
  return props?.['rk'] === false;
}

/**
 * The stored credential record, shared with the first-run claim so both registration paths write
 * exactly one format. `parsePasskey` reads it back at authentication time.
 */
export function passkeyRecord(
  outcome: RegistrationOutcome,
  userHandle: string,
  rpId: string,
): string {
  return serializePasskey({
    format: 'auth-mini-passkey',
    version: 1,
    id: outcome.credentialId,
    public_key: b64urlEncode(outcome.publicKey),
    counter: outcome.counter,
    transports: outcome.transports,
    user_handle: userHandle,
    rp_id: rpId,
  });
}

/**
 * Legacy `authorize_passkey_registration`: a strong session may manage passkeys; an Ed25519 session
 * may only add the caller's first one, so a device key can bootstrap a passkey but never extend it.
 */
async function authorizePasskeyRegistration(
  auth: AuthContext,
  deps: WebauthnDeps,
): Promise<{ firstOnly: boolean } | null> {
  if (mayManageCredentials(auth)) return { firstOnly: false };
  if (auth.authMethod !== 'ed25519') return null;
  if (await deps.webauthnStore.hasPasskey(auth.userId)) return null;
  return { firstOnly: true };
}

/** POST /webauthn/register/options — issue a discoverable-credential challenge for the caller. */
export async function handleWebauthnRegisterOptions(request: Request, deps: WebauthnDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');
  if ((await authorizePasskeyRegistration(auth, deps)) === null) {
    return errorResponse(403, 'insufficient_authentication_method');
  }

  try {
    rejectUnknownKeys(parseStrictJsonObject(await request.text()), []);
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  const config = resolveWebauthnConfig(await deps.adminStore.readConfig());
  if (config === null) return errorResponse(400, REGISTER_INVALID);

  const userName = (await deps.userStore.findEmail(auth.userId)) ?? auth.userId;
  const userHandle = await webauthnUserHandleText(auth.userId);
  const challenge = newChallenge();
  const requestId = uuidv4();
  const now = deps.now.toISOString();
  const expiresAt = new Date(deps.now.getTime() + WEBAUTHN_CHALLENGE_SECONDS * 1000).toISOString();

  // Only one registration challenge per user may be live; the legacy handler spends the previous
  // one here rather than letting them pile up.
  await deps.webauthnStore.expirePendingRegistrations(auth.userId, now);
  await deps.webauthnStore.insertChallenge({
    requestId,
    type: 'register',
    stateJson: JSON.stringify({ challenge, user_handle: userHandle }),
    userId: auth.userId,
    expiresAt,
    rpId: config.rpId,
    rpName: config.rpName,
    origin: config.origin,
    now,
  });

  return jsonResponse({
    ...registrationOptions({ challenge, rpId: config.rpId, rpName: config.rpName, userHandle, userName }),
    request_id: requestId,
  });
}

/** POST /webauthn/register/verify — check the ceremony, then store the neutral credential. */
export async function handleWebauthnRegisterVerify(request: Request, deps: WebauthnDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');
  const authorization = await authorizePasskeyRegistration(auth, deps);
  if (authorization === null) return errorResponse(403, 'insufficient_authentication_method');

  let requestId: string;
  let credential: RegistrationResponseJSON;
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['request_id', 'credential']);
    const parsedId = body['request_id'];
    if (typeof parsedId !== 'string' || !isUuid(parsedId)) throw new StrictJsonError('invalid_field');
    requestId = parsedId;
    const parsedCredential = parseRegistrationCredential(body['credential']);
    if (parsedCredential === null) throw new StrictJsonError('invalid_field');
    credential = parsedCredential;
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  const now = deps.now.toISOString();
  // `get_valid_register_challenge` in the legacy server filters on the same three conditions; a
  // replay must be refused before anything is written, or the duplicate credential id in the batch
  // would surface as a database error instead of a ceremony failure.
  const challenge = await deps.webauthnStore.findChallenge(requestId, 'register');
  if (
    challenge === null ||
    challenge.userId !== auth.userId ||
    challenge.consumedAt !== null ||
    challenge.expiresAt <= now
  ) {
    return errorResponse(400, REGISTER_INVALID);
  }

  if (reportsNonDiscoverable(credential.clientExtensionResults)) return errorResponse(400, REGISTER_INVALID);

  let state: { challenge?: unknown; user_handle?: unknown };
  try {
    state = JSON.parse(challenge.stateJson) as { challenge?: unknown; user_handle?: unknown };
  } catch {
    return errorResponse(400, REGISTER_INVALID);
  }
  if (typeof state.challenge !== 'string' || typeof state.user_handle !== 'string') {
    return errorResponse(400, REGISTER_INVALID);
  }

  const outcome = await verifyRegistrationCeremony({
    response: credential,
    challenge: state.challenge,
    origin: challenge.origin,
    rpId: challenge.rpId,
  });
  if (outcome === null) return errorResponse(400, REGISTER_INVALID);

  // Checking before the batch keeps the legacy behaviour where a rejected first-passkey rule does
  // not spend the challenge; the conditional INSERT is the second line of defence for the race.
  if (authorization.firstOnly && (await deps.webauthnStore.hasPasskey(auth.userId))) {
    return errorResponse(403, 'insufficient_authentication_method');
  }

  const passkeyJson = passkeyRecord(outcome, state.user_handle, challenge.rpId);

  const stored = await deps.webauthnStore.completeRegistration({
    requestId,
    credentialId: outcome.credentialId,
    userId: auth.userId,
    passkeyJson,
    rpId: challenge.rpId,
    firstOnly: authorization.firstOnly,
    now,
  });

  if (!stored.consumed) return errorResponse(400, REGISTER_INVALID);
  // A refused insert is the first-passkey guard, unless the credential id itself already exists.
  if (!stored.stored) {
    return errorResponse(authorization.firstOnly ? 403 : 400, authorization.firstOnly ? 'insufficient_authentication_method' : REGISTER_INVALID);
  }

  return jsonResponse({ ok: true });
}

/** POST /webauthn/authenticate/options — anonymous challenge for a discoverable sign-in. */
export async function handleWebauthnAuthenticationOptions(request: Request, deps: WebauthnDeps): Promise<Response> {
  try {
    rejectUnknownKeys(parseStrictJsonObject(await request.text()), []);
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  const config = resolveWebauthnConfig(await deps.adminStore.readConfig());
  if (config === null) return errorResponse(400, AUTHENTICATE_INVALID);

  const challenge = newChallenge();
  const requestId = uuidv4();
  const now = deps.now.toISOString();
  const expiresAt = new Date(deps.now.getTime() + WEBAUTHN_CHALLENGE_SECONDS * 1000).toISOString();

  await deps.webauthnStore.insertChallenge({
    requestId,
    type: 'authenticate',
    stateJson: JSON.stringify({ challenge }),
    userId: null,
    expiresAt,
    rpId: config.rpId,
    rpName: config.rpName,
    origin: config.origin,
    now,
  });

  return jsonResponse({
    ...authenticationOptions({ challenge, rpId: config.rpId }),
    request_id: requestId,
  });
}

/** POST /webauthn/authenticate/verify — verify an assertion and mint a session. */
export async function handleWebauthnAuthenticationVerify(request: Request, deps: WebauthnDeps): Promise<Response> {
  let requestId: string;
  let credential: AuthenticationResponseJSON;
  let audiences: string[];
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['request_id', 'credential', 'redirect_uri', 'aud', 'audiences']);
    const parsedId = body['request_id'];
    if (typeof parsedId !== 'string' || !isUuid(parsedId)) throw new StrictJsonError('invalid_field');
    requestId = parsedId;
    const parsedCredential = parseAuthenticationCredential(body['credential']);
    if (parsedCredential === null) throw new StrictJsonError('invalid_field');
    credential = parsedCredential;
    audiences = resolveAudiences(deps.issuer, {
      redirectUri: optionalString(body, 'redirect_uri') ?? undefined,
      aud: optionalString(body, 'aud') ?? undefined,
      audiences: readAudiences(body),
    });
  } catch (error) {
    if (error instanceof AudienceError || error instanceof StrictJsonError) return errorResponse(400, 'invalid_request');
    throw error;
  }

  const now = deps.now.toISOString();
  const challenge = await deps.webauthnStore.findChallenge(requestId, 'authenticate');
  if (challenge === null || challenge.consumedAt !== null || challenge.expiresAt <= now) {
    return errorResponse(400, AUTHENTICATE_INVALID);
  }

  let state: { challenge?: unknown };
  try {
    state = JSON.parse(challenge.stateJson) as { challenge?: unknown };
  } catch {
    return errorResponse(400, AUTHENTICATE_INVALID);
  }
  if (typeof state.challenge !== 'string') return errorResponse(400, AUTHENTICATE_INVALID);

  const stored = await deps.webauthnStore.findCredential(credential.id, challenge.rpId);
  if (stored === null) return errorResponse(400, AUTHENTICATE_INVALID);

  const passkey = parsePasskey(stored.passkeyJson);
  if (passkey === null) return errorResponse(400, AUTHENTICATE_INVALID);

  const assertion = await verifyAssertionCeremony({
    response: credential,
    challenge: state.challenge,
    origin: challenge.origin,
    rpId: challenge.rpId,
    credential: passkey,
  });
  if (assertion === null) return errorResponse(400, AUTHENTICATE_INVALID);

  const completed = await deps.webauthnStore.completeAuthentication({
    requestId,
    credentialId: passkey.id,
    rpId: challenge.rpId,
    passkeyJson: serializePasskey({ ...passkey, counter: assertion.newCounter }),
    now,
  });
  if (!completed.consumed || !completed.updated) return errorResponse(400, AUTHENTICATE_INVALID);

  const pair = await mintSession({
    keyStore: deps.keyStore,
    sessionStore: deps.sessionStore,
    issuer: deps.issuer,
    userId: stored.userId,
    authMethod: 'webauthn',
    sourceAuthMethod: null,
    audiences,
    ip: deps.clientIp,
    userAgent: deps.userAgent,
    isAdmin: await deps.userStore.isAdmin(stored.userId),
    now: deps.now,
  });

  return jsonResponse(tokenJson(pair));
}

/** DELETE /webauthn/credentials/{id} — owners only, and only from a strong session. */
export async function handleWebauthnCredentialDelete(
  request: Request,
  deps: WebauthnDeps,
  credentialId: string,
): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');
  if (!mayManageCredentials(auth)) return errorResponse(403, 'insufficient_authentication_method');

  const deleted = await deps.webauthnStore.deleteCredential(credentialId, auth.userId);
  if (!deleted) return errorResponse(404, 'credential_not_found');
  return jsonResponse({ ok: true });
}

function readAudiences(body: Record<string, unknown>): string[] | undefined {
  const raw = body['audiences'];
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw) || raw.length === 0 || !raw.every((value) => typeof value === 'string')) {
    throw new StrictJsonError('invalid_field');
  }
  return raw as string[];
}
