/** Token material rules copied from auth-mini's session.rs so migrated sessions stay valid. */

export const ACCESS_TOKEN_SECONDS = 900;
export const REFRESH_TOKEN_SECONDS = 2_592_000;

/** Legacy `random_token()`: `lower(hex(randomblob(32)))` -> 64 lowercase hex chars. */
export function randomHex(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/** Legacy `hash_value()`: lowercase hex of SHA-256 over the UTF-8 bytes. */
export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  let out = '';
  for (const byte of new Uint8Array(digest)) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function uuidv4(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Legacy `now_text()`: RFC 3339 with fixed millisecond precision and a `Z` suffix. */
export function nowRfc3339Millis(): string {
  return new Date().toISOString();
}
