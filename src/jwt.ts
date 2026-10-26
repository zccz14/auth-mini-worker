import type { Ed25519PrivateJwk, Ed25519PublicJwk } from './crypto/ed25519';
import { importPrivateKey, importPublicKey, signBytes, verifyBytes } from './crypto/ed25519';
import { b64urlDecode, b64urlDecodeText, b64urlEncode, b64urlEncodeText } from './crypto/b64url';

/** Access-token payload, claim for claim, as `sign_access_token` in the legacy server. */
export interface AccessTokenClaims {
  sub: string;
  sid: string;
  iss: string;
  aud: string | string[];
  amr: string[];
  auth_admin: boolean;
  typ: 'access';
  iat: number;
  exp: number;
}

export interface AccessTokenInput {
  userId: string;
  sessionId: string;
  issuer: string;
  audiences: readonly string[];
  authenticationMethods: readonly string[];
  authAdmin: boolean;
  nowSeconds: number;
  lifetimeSeconds: number;
}

function assertAudiences(audiences: readonly string[]): string[] {
  const normalized = audiences.map((value) => value.trim()).filter((value) => value.length > 0);
  if (normalized.length === 0) throw new Error('audience_required');
  return [...new Set(normalized)];
}

/** A single audience serializes as a string, several as an array — legacy `audience_json`. */
export function audienceJson(audiences: readonly string[]): string | string[] {
  const normalized = assertAudiences(audiences);
  return normalized.length === 1 ? normalized[0]! : normalized;
}

export function buildAccessTokenClaims(input: AccessTokenInput): AccessTokenClaims {
  if (!input.userId) throw new Error('user_id_required');
  if (!input.sessionId) throw new Error('session_id_required');
  if (!input.issuer) throw new Error('issuer_required');
  return {
    sub: input.userId,
    sid: input.sessionId,
    iss: input.issuer,
    aud: audienceJson(input.audiences),
    amr: [...input.authenticationMethods],
    auth_admin: input.authAdmin,
    typ: 'access',
    iat: input.nowSeconds,
    exp: input.nowSeconds + input.lifetimeSeconds,
  };
}

export async function signAccessToken(
  key: { kid: string; privateJwk: Ed25519PrivateJwk },
  claims: AccessTokenClaims,
): Promise<string> {
  const header = { alg: 'EdDSA', kid: key.kid, typ: 'JWT' };
  const encodedHeader = b64urlEncodeText(JSON.stringify(header));
  const encodedPayload = b64urlEncodeText(JSON.stringify(claims));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const cryptoKey = await importPrivateKey(key.privateJwk);
  const signature = await signBytes(cryptoKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64urlEncode(signature)}`;
}

export interface VerifyKey {
  kid: string;
  publicJwk: Ed25519PublicJwk;
}

/**
 * Verifies signature, `typ` and expiry. Returns null instead of throwing so callers map
 * every failure to the legacy `invalid_access_token` response.
 */
export async function verifyAccessToken(key: VerifyKey, token: string, nowSeconds: number): Promise<AccessTokenClaims | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];

  let header: { alg?: unknown; kid?: unknown; typ?: unknown };
  try {
    header = JSON.parse(b64urlDecodeText(encodedHeader)) as typeof header;
  } catch {
    return null;
  }
  if (header.alg !== 'EdDSA' || header.kid !== key.kid) return null;

  let verified = false;
  try {
    const cryptoKey = await importPublicKey(key.publicJwk);
    verified = await verifyBytes(
      cryptoKey,
      b64urlDecode(encodedSignature),
      new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
    );
  } catch {
    return null;
  }
  if (!verified) return null;

  let claims: AccessTokenClaims;
  try {
    claims = JSON.parse(b64urlDecodeText(encodedPayload)) as AccessTokenClaims;
  } catch {
    return null;
  }
  if (claims.typ !== 'access') return null;
  if (typeof claims.exp !== 'number' || claims.exp <= nowSeconds) return null;
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) return null;
  if (typeof claims.sid !== 'string' || claims.sid.length === 0) return null;
  return claims;
}

/** Header peek, used to pick the key by `kid` before verifying. */
export function decodeJwtHeader(token: string): { alg?: string; kid?: string; typ?: string } | null {
  const [encodedHeader] = token.split('.');
  if (!encodedHeader) return null;
  try {
    return JSON.parse(b64urlDecodeText(encodedHeader)) as { alg?: string; kid?: string; typ?: string };
  } catch {
    return null;
  }
}

/** `aud` is a string for a single audience and an array for several. */
export function claimAudiences(aud: string | string[] | undefined): string[] {
  if (typeof aud === 'string') return aud.length === 0 ? [] : [aud];
  if (Array.isArray(aud)) return aud.filter((value): value is string => typeof value === 'string');
  return [];
}
