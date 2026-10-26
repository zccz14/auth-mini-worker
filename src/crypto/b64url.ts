/**
 * base64url without padding, byte-identical to the Rust server's `encode_segment`
 * / `decode_segment` (auth-mini rust-backend/src/jwks.rs). JWT segments must decode
 * the way the legacy server wrote them, so this is hand-rolled instead of Buffer.
 */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i += 1) LOOKUP[ALPHABET.charCodeAt(i)] = i;

export function b64urlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += ALPHABET[(chunk >> 18) & 63]! + ALPHABET[(chunk >> 12) & 63]! + ALPHABET[(chunk >> 6) & 63]! + ALPHABET[chunk & 63]!;
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const chunk = bytes[i]! << 16;
    out += ALPHABET[(chunk >> 18) & 63]! + ALPHABET[(chunk >> 12) & 63]!;
  } else if (remaining === 2) {
    const chunk = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += ALPHABET[(chunk >> 18) & 63]! + ALPHABET[(chunk >> 12) & 63]! + ALPHABET[(chunk >> 6) & 63]!;
  }
  return out;
}

/** Strict decode: rejects padding, foreign characters and non-canonical trailing bits. */
export function b64urlDecode(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new Error('invalid_base64url');
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? LOOKUP[code]! : -1;
    if (value < 0) throw new Error('invalid_base64url');
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index] = (buffer >> bits) & 0xff;
      index += 1;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) throw new Error('invalid_base64url');
  return out.subarray(0, index);
}

export function b64urlEncodeText(text: string): string {
  return b64urlEncode(new TextEncoder().encode(text));
}

export function b64urlDecodeText(text: string): string {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(b64urlDecode(text));
}
