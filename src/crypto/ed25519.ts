import { b64urlDecode, b64urlEncode } from './b64url';

export interface Ed25519PublicJwk extends JsonWebKey {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
}

export interface Ed25519PrivateJwk extends Ed25519PublicJwk {
  d: string;
}

const ALGORITHM = { name: 'Ed25519' } as const;

export async function importPublicKey(jwk: Ed25519PublicJwk): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, ALGORITHM, false, ['verify']);
}

export async function importPrivateKey(jwk: Ed25519PrivateJwk): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, ALGORITHM, false, ['sign']);
}

export async function signBytes(key: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign(ALGORITHM, key, message));
}

export async function verifyBytes(key: CryptoKey, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
  try {
    return await crypto.subtle.verify(ALGORITHM, key, signature, message);
  } catch {
    return false;
  }
}

export interface GeneratedKeyPair {
  publicJwk: Ed25519PublicJwk;
  privateJwk: Ed25519PrivateJwk;
}

/**
 * Generates a fresh Ed25519 key pair. Only ever used locally (rotation, tests,
 * first boot): production key material is imported from the legacy server.
 */
export async function generateKeyPair(): Promise<GeneratedKeyPair> {
  const pair = (await crypto.subtle.generateKey(ALGORITHM, true, ['sign', 'verify'])) as CryptoKeyPair;
  const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as Ed25519PublicJwk;
  const privateJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as Ed25519PrivateJwk;
  return { publicJwk, privateJwk };
}

/** JWK `d` (base64url private scalar) -> CryptoKey, matching the legacy storage layout. */
export async function importPrivateScalar(privateJwk: Ed25519PrivateJwk): Promise<CryptoKey> {
  const scalar = b64urlDecode(privateJwk.d);
  if (scalar.length !== 32) throw new Error('invalid_private_key');
  return importPrivateKey(privateJwk);
}

export { b64urlEncode };
