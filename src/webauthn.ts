/**
 * WebAuthn is the one place where a library earns its keep: CBOR, COSE keys, attestation
 * statements and DER signatures are security-critical and easy to get subtly wrong.
 * `@simplewebauthn/server` verifies ceremonies on WebCrypto — the same implementation
 * auth-mini's original Node backend used before the port to Rust — so the browser-visible
 * behaviour stays the one real clients were tested against.
 *
 * Everything the contract pins down stays ours: the option projections (the legacy server
 * narrows what webauthn-rs would emit), the user handle derivation, the RP/origin
 * normalisation, and the stored credential format.
 */
import { verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { b64urlDecode, b64urlEncode } from './crypto/b64url';
import type { AppConfig } from './stores';

/** Legacy `WEBAUTHN_CHALLENGE_SECONDS`; the options also advertise it as `timeout`. */
export const WEBAUTHN_CHALLENGE_SECONDS = 300;
export const WEBAUTHN_TIMEOUT_MILLIS = 300_000;

/**
 * `COSEAlgorithm::secure_algs()` in webauthn-rs 0.5.5 is exactly ES256 and RS256. Advertising or
 * accepting EdDSA here would widen the contract in a way migrated authenticators never saw.
 */
export const SUPPORTED_COSE_ALGORITHMS: readonly number[] = [-7, -257];

export interface WebauthnConfig {
  origin: string;
  rpId: string;
  rpName: string;
}

/**
 * Port of `resolve_options_input`: the issuer becomes the origin, the stored rp_id must be the
 * origin host or a parent domain of it, and anything unparseable fails closed.
 */
export function resolveWebauthnConfig(config: Pick<AppConfig, 'issuer' | 'rpId' | 'brandName'>): WebauthnConfig | null {
  const origin = normalizeAllowedOrigin(config.issuer);
  if (origin === null) return null;
  const hostname = originHostname(origin);
  if (hostname === null) return null;
  const rpId = normalizeRpId(config.rpId);
  if (rpId === null) return null;
  const rpName = config.brandName.trim();
  if (rpName.length === 0) return null;
  if (!isRpIdAllowedForOrigin(hostname, rpId)) return null;
  return { origin, rpId, rpName };
}

/** Legacy `normalize_allowed_origin`: scheme + host + optional non-default port, nothing else. */
export function normalizeAllowedOrigin(input: string): string | null {
  if (input === 'null' || input.includes('@') || input.includes('?') || input.includes('#')) return null;
  const separator = input.indexOf('://');
  if (separator < 0) return null;

  const protocol = input.slice(0, separator).toLowerCase();
  if (protocol !== 'http' && protocol !== 'https') return null;

  const rest = input.slice(separator + 3);
  if (rest.length === 0 || rest.includes('/')) return null;

  const parts = splitHostPort(rest);
  if (parts === null) return null;

  const hostname = parts.host.replace(/\.+$/, '').toLowerCase();
  if (hostname.length === 0) return null;

  let port = '';
  if (parts.port !== null) {
    if ((protocol === 'http' && parts.port === '80') || (protocol === 'https' && parts.port === '443')) {
      port = '';
    } else if (/^[0-9]+$/.test(parts.port)) {
      port = `:${parts.port}`;
    } else {
      return null;
    }
  }

  return `${protocol}://${hostname}${port}`;
}

/** Legacy `normalize_rp_id`: lowercase DNS name, no scheme, no port, no empty labels. */
export function normalizeRpId(input: string): string | null {
  const trimmed = input.trim().toLowerCase().replace(/\.+$/, '');
  if (trimmed.length === 0) return null;
  if (/[:/@\s]/.test(trimmed)) return null;
  if (trimmed.split('.').some((label) => label.length === 0)) return null;
  if (!/^[a-z0-9.-]+$/.test(trimmed)) return null;
  return trimmed;
}

/** Legacy `is_rp_id_allowed_for_origin`: equal, or a parent domain of the origin host. */
export function isRpIdAllowedForOrigin(originHostname: string, rpId: string): boolean {
  if (originHostname === rpId) return true;
  if (isIpAddress(originHostname) || isIpAddress(rpId)) return false;
  if (originHostname === 'localhost' || rpId === 'localhost') return false;
  return originHostname.endsWith(`.${rpId}`);
}

export function originHostname(origin: string): string | null {
  const separator = origin.indexOf('://');
  if (separator < 0) return null;
  const parts = splitHostPort(origin.slice(separator + 3));
  return parts === null ? null : parts.host;
}

function splitHostPort(value: string): { host: string; port: string | null } | null {
  if (value.startsWith('[')) return null;
  const separator = value.lastIndexOf(':');
  if (separator < 0) return { host: value, port: null };
  return { host: value.slice(0, separator), port: value.slice(separator + 1) };
}

function isIpAddress(value: string): boolean {
  if (value.includes(':')) return true;
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => part.length > 0 && /^[0-9]+$/.test(part));
}

const USER_HANDLE_PREFIX = new TextEncoder().encode('auth-mini-webauthn-user-handle\0');

/**
 * Port of `user_webauthn_id`: SHA-256 over a fixed prefix and the user id, truncated to 16 bytes
 * and stamped as a version-5 UUID. Migrated credentials carry this handle, and a discoverable
 * sign-in hands it back, so the derivation cannot drift.
 */
export async function webauthnUserHandle(userId: string): Promise<Uint8Array> {
  const idBytes = new TextEncoder().encode(userId);
  const input = new Uint8Array(USER_HANDLE_PREFIX.length + idBytes.length);
  input.set(USER_HANDLE_PREFIX, 0);
  input.set(idBytes, USER_HANDLE_PREFIX.length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  const handle = digest.slice(0, 16);
  handle[6] = (handle[6]! & 0x0f) | 0x50;
  handle[8] = (handle[8]! & 0x3f) | 0x80;
  return handle;
}

export async function webauthnUserHandleText(userId: string): Promise<string> {
  return b64urlEncode(await webauthnUserHandle(userId));
}

export function newChallenge(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * The registration options the legacy server actually sends: webauthn-rs state asks for a
 * discouraged resident key, but `project_registration_public_key` narrows the outbound JSON to
 * resident-key-required with the credProps extension and drops everything else. The field names
 * and their order follow serde_json's map ordering so the response stays comparable byte for byte.
 */
export function registrationOptions(input: {
  challenge: string;
  rpId: string;
  rpName: string;
  userHandle: string;
  userName: string;
}): Record<string, unknown> {
  return {
    publicKey: {
      authenticatorSelection: { requireResidentKey: true, residentKey: 'required', userVerification: 'required' },
      challenge: input.challenge,
      extensions: { credProps: true },
      pubKeyCredParams: SUPPORTED_COSE_ALGORITHMS.map((alg) => ({ alg, type: 'public-key' })),
      rp: { id: input.rpId, name: input.rpName },
      timeout: WEBAUTHN_TIMEOUT_MILLIS,
      user: { displayName: input.userName, id: input.userHandle, name: input.userName },
    },
  };
}

/** `authentication_options` sends no `allowCredentials`: every credential is discoverable. */
export function authenticationOptions(input: { challenge: string; rpId: string }): Record<string, unknown> {
  return {
    publicKey: {
      challenge: input.challenge,
      rpId: input.rpId,
      timeout: WEBAUTHN_TIMEOUT_MILLIS,
      userVerification: 'required',
    },
  };
}

export interface RegistrationOutcome {
  credentialId: string;
  publicKey: Uint8Array;
  counter: number;
  transports: string[];
}

/**
 * Returns null on any failure — a bad challenge, a foreign origin, an unsupported algorithm or a
 * broken attestation statement all collapse into `invalid_webauthn_registration`, exactly like
 * the legacy handler, so a caller learns nothing about which check failed.
 */
export async function verifyRegistrationCeremony(input: {
  response: RegistrationResponseJSON;
  challenge: string;
  origin: string;
  rpId: string;
}): Promise<RegistrationOutcome | null> {
  let result: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    result = await verifyRegistrationResponse({
      response: input.response,
      expectedChallenge: input.challenge,
      expectedOrigin: input.origin,
      expectedRPID: input.rpId,
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [...SUPPORTED_COSE_ALGORITHMS],
    });
  } catch {
    return null;
  }
  if (!result.verified) return null;

  const { credential } = result.registrationInfo;
  return {
    credentialId: credential.id,
    publicKey: new Uint8Array(credential.publicKey),
    counter: credential.counter,
    transports: [...(credential.transports ?? [])],
  };
}

export interface AssertionOutcome {
  newCounter: number;
}

/**
 * Verifies one assertion against the stored public key. The legacy path identifies the user by
 * which credential matched and never looked at `userHandle`; we additionally require it to agree
 * with the stored handle when the authenticator sends one, which is what a discoverable ceremony
 * promises.
 */
export async function verifyAssertionCeremony(input: {
  response: AuthenticationResponseJSON;
  challenge: string;
  origin: string;
  rpId: string;
  credential: StoredPasskey;
}): Promise<AssertionOutcome | null> {
  const userHandle = input.response.response.userHandle;
  if (typeof userHandle === 'string' && userHandle.length > 0 && userHandle !== input.credential.user_handle) {
    return null;
  }

  let publicKey: Uint8Array<ArrayBuffer>;
  try {
    // Copying into a fresh buffer also satisfies WebCrypto's `BufferSource` type, which refuses
    // views that could be backed by a SharedArrayBuffer.
    publicKey = new Uint8Array(b64urlDecode(input.credential.public_key));
  } catch {
    return null;
  }

  let result: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    result = await verifyAuthenticationResponse({
      response: input.response,
      expectedChallenge: input.challenge,
      expectedOrigin: input.origin,
      expectedRPID: input.rpId,
      credential: {
        id: input.credential.id,
        publicKey,
        counter: input.credential.counter,
        transports: input.credential.transports as never,
      },
      requireUserVerification: true,
    });
  } catch {
    return null;
  }
  if (!result.verified) return null;
  if (result.authenticationInfo.credentialID !== input.credential.id) return null;

  return { newCounter: result.authenticationInfo.newCounter };
}

/**
 * What lands in `webauthn_credentials.passkey_json`.
 *
 * The column keeps its legacy name, but the value is neutral: webauthn-rs's own serde shape is
 * not something this codebase parses, so the cutover exporter rewrites legacy rows into this
 * form (`tools/webauthn-export`). `format`/`version` make a legacy row fail closed instead of
 * being misread as one of ours.
 */
export interface StoredPasskey {
  format: 'auth-mini-passkey';
  version: 1;
  id: string;
  public_key: string;
  counter: number;
  transports: string[];
  user_handle: string;
  rp_id: string;
}

export function serializePasskey(passkey: StoredPasskey): string {
  return JSON.stringify({
    format: passkey.format,
    version: passkey.version,
    id: passkey.id,
    public_key: passkey.public_key,
    counter: passkey.counter,
    transports: passkey.transports,
    user_handle: passkey.user_handle,
    rp_id: passkey.rp_id,
  });
}

export function parsePasskey(json: string): StoredPasskey | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const value = parsed as Record<string, unknown>;
  if (value['format'] !== 'auth-mini-passkey' || value['version'] !== 1) return null;
  const id = value['id'];
  const publicKey = value['public_key'];
  const counter = value['counter'];
  const transports = value['transports'];
  const userHandle = value['user_handle'];
  const rpId = value['rp_id'];
  if (typeof id !== 'string' || id.length === 0) return null;
  if (typeof publicKey !== 'string' || publicKey.length === 0) return null;
  if (typeof counter !== 'number' || !Number.isInteger(counter) || counter < 0) return null;
  if (!Array.isArray(transports) || !transports.every((entry) => typeof entry === 'string')) return null;
  if (typeof userHandle !== 'string') return null;
  if (typeof rpId !== 'string' || rpId.length === 0) return null;
  return {
    format: 'auth-mini-passkey',
    version: 1,
    id,
    public_key: publicKey,
    counter,
    transports: transports as string[],
    user_handle: userHandle,
    rp_id: rpId,
  };
}
