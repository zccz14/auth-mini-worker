/** Port of auth-mini rust-backend/src/setup.rs normalisers. */

export class AdminValidationError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'AdminValidationError';
  }
}

function isIpAddress(value: string): boolean {
  if (value.includes(':')) return true;
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => part.length > 0 && /^[0-9]+$/.test(part));
}

function hostOf(url: URL): string {
  const host = url.hostname.toLowerCase();
  return host.endsWith('.') ? host.slice(0, -1) : host;
}

/** `scheme://host[:port]/` only — no credentials, query, fragment or path. */
export function normalizeAllowedOrigin(input: string): string {
  const trimmed = input.trim();
  if (trimmed.length === 0) throw new AdminValidationError('empty_origin');
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new AdminValidationError('invalid_origin');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new AdminValidationError('invalid_origin');
  if (url.username || url.password || url.search || url.hash) throw new AdminValidationError('invalid_origin');
  if (url.pathname !== '/') throw new AdminValidationError('invalid_origin');
  return `${url.protocol}//${hostOf(url)}${url.port ? `:${url.port}` : ''}`;
}

export function normalizeRpId(input: string): string {
  const rpId = input.trim().toLowerCase().replace(/\.+$/, '');
  if (
    rpId.length === 0 ||
    rpId.includes(':') ||
    rpId.includes('/') ||
    rpId.includes('@') ||
    rpId.includes(' ') ||
    rpId.split('.').some((label) => label.length === 0) ||
    !/^[a-z0-9.-]+$/.test(rpId)
  ) {
    throw new AdminValidationError('invalid_rp_id');
  }
  return rpId;
}

export function normalizeBrandName(input: string): string {
  const name = input.trim();
  if (name.length === 0) throw new AdminValidationError('empty_brand_name');
  return name;
}

export function isRpIdAllowedForOrigin(originHostname: string, rpId: string): boolean {
  if (originHostname === rpId) return true;
  if (isIpAddress(originHostname) || isIpAddress(rpId) || originHostname === 'localhost' || rpId === 'localhost') {
    return false;
  }
  return originHostname.endsWith(`.${rpId}`);
}

export function validateRpIdForIssuer(issuer: string, rpId: string): void {
  const host = hostOf(new URL(issuer));
  if (!isRpIdAllowedForOrigin(host, rpId)) throw new AdminValidationError('rp_id_mismatch');
}

/** A real DNS name: `localhost` for local development, otherwise at least two labels and no numeric TLD. */
function isDnsName(rpId: string): boolean {
  if (rpId === 'localhost') return true;
  const labels = rpId.split('.');
  return labels.length > 1 && !/^[0-9]+$/.test(labels[labels.length - 1]!);
}

/**
 * The relying party a first-run claim is bound to: whatever host the owner actually reached us on.
 *
 * Nothing else can supply it. A fresh database still says `localhost`, and changing that needs an
 * administrator token — which is exactly what the claim is there to create. WebAuthn also pins
 * `rp_id` to the origin for the lifetime of every credential, so an IP literal or a one-label host
 * would lock the instance into a configuration no authenticator can accept. The page shows these
 * two values before the owner confirms, and sends them back so a stale tab cannot claim a host
 * nobody looked at.
 */
export function deriveSetupRelyingParty(requestUrl: string): { issuer: string; rpId: string } | null {
  let url: URL;
  try {
    url = new URL(requestUrl);
  } catch {
    return null;
  }
  let issuer: string;
  let rpId: string;
  try {
    issuer = normalizeAllowedOrigin(url.origin);
    rpId = normalizeRpId(url.hostname);
  } catch {
    return null;
  }
  if (!isDnsName(rpId)) return null;
  if (!isRpIdAllowedForOrigin(url.hostname.toLowerCase(), rpId)) return null;
  return { issuer, rpId };
}
