import { base58Decode } from './crypto/base58';
import { b64urlDecode } from './crypto/b64url';
import { randomHex } from './crypto/tokens';

export const ED25519_CHALLENGE_SECONDS = 300;

export function newChallenge(): string {
  // Legacy `random_token()`: 32 random bytes as 64 lowercase hex characters.
  return randomHex(32);
}

export function decodePublicKey(publicKey: string): Uint8Array | null {
  try {
    const bytes = base58Decode(publicKey);
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

/**
 * Verifies a device signature over the challenge.
 *
 * The signed message is the raw UTF-8 bytes of the challenge string, and the signature is
 * base64url without padding — both copied from the legacy server, because every already
 * provisioned device key depends on them.
 */
export async function verifyChallengeSignature(
  challenge: string,
  publicKey: string,
  signature: string,
): Promise<boolean> {
  const keyBytes = decodePublicKey(publicKey);
  if (!keyBytes) return false;

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = b64urlDecode(signature);
  } catch {
    return false;
  }
  if (signatureBytes.length !== 64) return false;

  try {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signatureBytes, new TextEncoder().encode(challenge));
  } catch {
    return false;
  }
}
