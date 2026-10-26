import { issuerAudience } from './audience';
import { claimAudiences, decodeJwtHeader, verifyAccessToken } from './jwt';
import type { SigningKeyStore } from './jwks';
import { verifyingKeyByKid } from './jwks';
import type { SessionRow, SessionStore } from './stores';

export interface AuthContext {
  userId: string;
  sessionId: string;
  authMethod: string;
  audiences: string[];
}

export interface AuthDeps {
  keyStore: SigningKeyStore;
  sessionStore: SessionStore;
  issuer: string;
  now: Date;
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get('authorization');
  if (!header) return null;
  const match = /^Bearer (.+)$/i.exec(header.trim());
  return match?.[1] ?? null;
}

function sameAudiences(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const sortedLeft = [...left].sort();
  const sortedRight = [...right].sort();
  return sortedLeft.every((value, index) => value === sortedRight[index]);
}

/**
 * Port of `authenticate_access_token`: signature by `kid`, then the session row must still be
 * live and still agree on user and audiences. A token whose session was logged out, expired or
 * re-scoped stops working immediately even though its signature is still valid.
 */
export async function authenticateAccessToken(request: Request, deps: AuthDeps): Promise<AuthContext | null> {
  const token = bearerToken(request);
  if (!token) return null;

  const header = decodeJwtHeader(token);
  if (!header?.kid) return null;

  const key = await verifyingKeyByKid(deps.keyStore, header.kid);
  if (!key) return null;

  const claims = await verifyAccessToken(key, token, Math.floor(deps.now.getTime() / 1000));
  if (!claims || claims.iss !== deps.issuer) return null;

  const session = await deps.sessionStore.find(claims.sid);
  if (!session) return null;
  if (session.expiresAt <= deps.now.toISOString()) return null;
  if (session.userId !== claims.sub) return null;
  if (!sameAudiences(session.audiences, claimAudiences(claims.aud))) return null;

  return {
    userId: claims.sub,
    sessionId: claims.sid,
    authMethod: session.authMethod,
    audiences: session.audiences,
  };
}

/** Legacy `require_self_audience`: /me is for the Auth Mini site itself, not delegated apps. */
export function hasSelfAudience(auth: AuthContext, issuer: string): boolean {
  return auth.audiences.includes(issuerAudience(issuer));
}

export function activeSessionJson(session: SessionRow): Record<string, unknown> {
  return {
    id: session.id,
    auth_method: session.authMethod,
    aud: JSON.stringify([...session.audiences]),
    ip: session.ip,
    user_agent: session.userAgent,
    expires_at: session.expiresAt,
    created_at: session.createdAt,
  };
}
