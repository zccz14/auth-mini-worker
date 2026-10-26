/**
 * Port of `ui-web/src/lib/login-callback.ts` from the legacy GUI: the login page receives a target
 * (a business app callback) and must refuse anything the server would refuse, so the two never
 * disagree about what a link means.
 */
import { api, type TokenPair } from './api';

export type LoginTarget =
  | { kind: 'self' }
  | { kind: 'redirect'; audiences: string[] | null; redirectUri: string; displayHost: string }
  | { kind: 'loopback'; audiences: string[]; redirectUri: string; displayHost: string };

export type InvalidReason = 'invalid_redirect_uri' | 'audience_rules' | 'https_required';

export type LoginRequest =
  | { status: 'ready'; state: string | null; target: LoginTarget }
  | { status: 'invalid'; reason: InvalidReason };

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

function normalizeHostname(hostname: string): string {
  return hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.+$/, '');
}

function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname);
}

/** An audience is a bare hostname: no scheme, port, path, query or fragment. */
export function normalizeAudience(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  if (/[\s/@:?#]/.test(trimmed)) return null;
  return normalizeHostname(trimmed);
}

function parseAudiences(raw: string | null): string[] | null {
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((item) => typeof item !== 'string')) return null;
  const normalized = parsed.map((item) => normalizeAudience(item));
  if (normalized.some((item) => item === null)) return null;
  const values = normalized as string[];
  return new Set(values).size === values.length ? values : null;
}

export function parseLoginRequest(routeSearch: string, documentSearch = ''): LoginRequest {
  const params = new URLSearchParams(routeSearch);
  const outer = new URLSearchParams(documentSearch);
  const pick = (key: string): string | null => (params.has(key) ? params.get(key) : outer.get(key));

  const redirectUri = (pick('redirect_uri') ?? '').trim();
  const audParam = pick('aud');
  const audiencesParam = pick('audiences');
  const state = pick('state');

  if (redirectUri.length === 0) {
    if (audParam !== null || audiencesParam !== null) {
      return { status: 'invalid', reason: 'audience_rules' };
    }
    return { status: 'ready', state, target: { kind: 'self' } };
  }

  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return { status: 'invalid', reason: 'invalid_redirect_uri' };
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { status: 'invalid', reason: 'invalid_redirect_uri' };
  }

  const hostname = normalizeHostname(parsed.hostname);
  const displayHost = parsed.host;

  if (isLoopback(hostname)) {
    if (audParam !== null && audiencesParam !== null) return { status: 'invalid', reason: 'audience_rules' };
    const declared = parseAudiences(audiencesParam);
    if (audiencesParam !== null && declared === null) return { status: 'invalid', reason: 'audience_rules' };
    const audiences = declared ?? (audParam === null ? null : [normalizeAudience(audParam)]);
    if (audiences === null || audiences.some((value) => value === null)) {
      return { status: 'invalid', reason: 'audience_rules' };
    }
    if (!audiences.includes(hostname)) return { status: 'invalid', reason: 'audience_rules' };
    return {
      status: 'ready',
      state,
      target: { kind: 'loopback', audiences: audiences as string[], redirectUri: parsed.toString(), displayHost },
    };
  }

  if (parsed.protocol !== 'https:') return { status: 'invalid', reason: 'https_required' };
  if (audParam !== null) return { status: 'invalid', reason: 'audience_rules' };

  const declared = parseAudiences(audiencesParam);
  if (audiencesParam !== null && declared === null) return { status: 'invalid', reason: 'audience_rules' };
  if (declared !== null && !declared.includes(hostname)) return { status: 'invalid', reason: 'audience_rules' };

  return {
    status: 'ready',
    state,
    target: { kind: 'redirect', audiences: declared, redirectUri: parsed.toString(), displayHost },
  };
}

/** The body `POST /session/authorize` expects for this target; `{}` for the main site itself. */
export function authorizeBody(target: LoginTarget): Record<string, unknown> {
  if (target.kind === 'self') return {};
  if (target.kind === 'loopback') return { redirect_uri: target.redirectUri, audiences: target.audiences };
  return target.audiences === null
    ? { redirect_uri: target.redirectUri }
    : { redirect_uri: target.redirectUri, audiences: target.audiences };
}

/** Where the browser lands afterwards: tokens ride in the fragment, never the query string. */
export function buildCallbackUrl(input: { redirectUri: string; state: string | null; tokens: TokenPair }): string {
  const target = new URL(input.redirectUri);
  const params = new URLSearchParams(target.hash.slice(1));
  params.set('access_token', input.tokens.access_token);
  params.set('token_type', input.tokens.token_type);
  params.set('session_id', input.tokens.session_id);
  params.set('refresh_token', input.tokens.refresh_token);
  params.set('expires_in', String(input.tokens.expires_in));
  if (input.state !== null) params.set('state', input.state);
  target.hash = params.toString();
  return target.toString();
}

export async function authorize(target: LoginTarget, accessToken: string): Promise<TokenPair> {
  const body = await api('/session/authorize', {
    method: 'POST',
    headers: { authorization: `Bearer ${accessToken}` },
    body: JSON.stringify(authorizeBody(target)),
  });
  return body as TokenPair;
}
