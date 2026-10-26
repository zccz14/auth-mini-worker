/**
 * Port of auth-mini rust-backend/src/audience.rs. The policy below decides what goes into
 * `aud`, and downstream backends scope their authorization by it, so it is copied rather
 * than reinvented.
 */

export class AudienceError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = 'AudienceError';
  }
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

function normalizeHost(hostname: string): string {
  const lower = hostname.toLowerCase();
  return lower.endsWith('.') ? lower.slice(0, -1) : lower;
}

function isAllowedLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(normalizeHost(hostname));
}

/** Legacy `is_loopback_redirect`: only these targets may receive the issuer audience. */
export function isLoopbackRedirect(redirectUri: string | undefined): boolean {
  if (redirectUri === undefined) return false;
  try {
    return isAllowedLoopback(new URL(redirectUri).hostname);
  } catch {
    return false;
  }
}

export function issuerAudience(issuer: string): string {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new AudienceError('invalid_issuer');
  }
  if (!url.hostname) throw new AudienceError('invalid_issuer');
  return normalizeHost(url.hostname);
}

/** An audience is a bare hostname: no scheme, no port, no path, no credentials. */
export function normalizeAudience(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new AudienceError('invalid_audience');
  if (/[\s/@:?#]/.test(trimmed)) throw new AudienceError('invalid_audience');
  return normalizeHost(trimmed);
}

/** Duplicates are an error, not something to silently collapse (legacy used a set + error). */
export function normalizeAudiences(values: readonly string[]): string[] {
  if (values.length === 0) throw new AudienceError('invalid_audience');
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = normalizeAudience(value);
    if (seen.has(normalized)) throw new AudienceError('invalid_audience');
    seen.add(normalized);
  }
  return [...seen].sort();
}

export interface AudienceRequest {
  redirectUri?: string | undefined;
  aud?: string | undefined;
  audiences?: readonly string[] | undefined;
}

export function resolveAudiences(issuer: string, request: AudienceRequest): string[] {
  if (request.aud !== undefined && request.audiences !== undefined) throw new AudienceError('invalid_audience');

  if (request.redirectUri === undefined) {
    if (request.aud !== undefined || request.audiences !== undefined) {
      throw new AudienceError('explicit_audience_not_allowed');
    }
    return [issuerAudience(issuer)];
  }

  let redirect: URL;
  try {
    redirect = new URL(request.redirectUri);
  } catch {
    throw new AudienceError('invalid_redirect_uri');
  }
  if (redirect.protocol !== 'http:' && redirect.protocol !== 'https:') {
    throw new AudienceError('invalid_redirect_uri');
  }
  if (!redirect.hostname) throw new AudienceError('invalid_redirect_uri');

  const loopback = isAllowedLoopback(redirect.hostname);
  if (!loopback && redirect.protocol !== 'https:') throw new AudienceError('invalid_redirect_uri');

  const callbackAudience = normalizeHost(redirect.hostname);
  const explicit =
    request.aud !== undefined ? [request.aud] : request.audiences !== undefined ? [...request.audiences] : undefined;

  if (loopback && explicit === undefined) throw new AudienceError('audience_required');

  const values = normalizeAudiences(explicit ?? [callbackAudience]);
  if (!values.includes(callbackAudience)) throw new AudienceError('audience_required');
  return values;
}
