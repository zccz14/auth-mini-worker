import { ACCESS_TOKEN_SECONDS, REFRESH_TOKEN_SECONDS, nowRfc3339Millis, randomHex, sha256Hex, uuidv4 } from './crypto/tokens';
import type { SessionRecord, SessionStore } from './stores';
import type { SigningKeyStore } from './jwks';
import { currentSigningKey } from './jwks';
import { buildAccessTokenClaims, signAccessToken } from './jwt';

export interface SessionDeps {
  keyStore: SigningKeyStore;
  sessionStore: SessionStore;
  issuer: string;
  userId: string;
  authMethod: string;
  sourceAuthMethod?: string | null;
  audiences: readonly string[];
  ip: string | null;
  userAgent: string | null;
  isAdmin: boolean;
  now: Date;
}

export interface TokenPair {
  sessionId: string;
  accessToken: string;
  refreshToken: string;
}

/** Port of `mint_session_tokens_for_audience`: row first, then the token pair. */
export async function mintSession(deps: SessionDeps): Promise<TokenPair> {
  const sessionId = uuidv4();
  const refreshToken = randomHex(32);
  const refreshTokenHash = await sha256Hex(refreshToken);
  const expiresAt = new Date(deps.now.getTime() + REFRESH_TOKEN_SECONDS * 1000).toISOString();

  const record: SessionRecord = {
    id: sessionId,
    userId: deps.userId,
    refreshTokenHash,
    authMethod: deps.authMethod,
    sourceAuthMethod: deps.sourceAuthMethod ?? null,
    audiences: deps.audiences,
    ip: deps.ip,
    userAgent: deps.userAgent,
    expiresAt,
  };
  await deps.sessionStore.insert(record);

  const key = await currentSigningKey(deps.keyStore);
  const authenticationMethods = deps.sourceAuthMethod ? [deps.authMethod, deps.sourceAuthMethod] : [deps.authMethod];
  const claims = buildAccessTokenClaims({
    userId: deps.userId,
    sessionId,
    issuer: deps.issuer,
    audiences: deps.audiences,
    authenticationMethods,
    authAdmin: deps.isAdmin,
    nowSeconds: Math.floor(deps.now.getTime() / 1000),
    lifetimeSeconds: ACCESS_TOKEN_SECONDS,
  });
  const accessToken = await signAccessToken({ kid: key.kid, privateJwk: key.privateJwk }, claims);

  return { sessionId, accessToken, refreshToken };
}

/** `token_json` shape, as the SDKs and the OpenAPI schema expect it. */
export function tokenJson(pair: TokenPair): Record<string, unknown> {
  return {
    session_id: pair.sessionId,
    access_token: pair.accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_SECONDS,
    refresh_token: pair.refreshToken,
  };
}

export { nowRfc3339Millis };
