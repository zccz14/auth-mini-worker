/**
 * A software authenticator: real P-256 keys, real CBOR, real signatures, no browser.
 *
 * Both registration paths (the authenticated passkey route and the one-time administrator claim)
 * are verified by the same code, so they are also exercised with the same authenticator — a second
 * implementation of the ceremony would only prove that two wrong things agree.
 */
import { b64urlEncode } from '../src/crypto/b64url';

/** The relying party every ceremony test defaults to; overrides exist to prove mismatches fail. */
export const DEFAULT_ORIGIN = 'https://auth.ntnl.io';
export const DEFAULT_RP_ID = 'auth.ntnl.io';

const enc = new TextEncoder();

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function be16(value: number): Uint8Array {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}

function be32(value: number): Uint8Array {
  return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function cborHead(major: number, length: number): number[] {
  if (length < 24) return [(major << 5) | length];
  if (length < 256) return [(major << 5) | 24, length];
  return [(major << 5) | 25, (length >> 8) & 0xff, length & 0xff];
}

function cborText(value: string): number[] {
  const bytes = [...enc.encode(value)];
  return [...cborHead(3, bytes.length), ...bytes];
}

function cborBytes(value: Uint8Array): number[] {
  return [...cborHead(2, value.length), ...value];
}

function cborInt(value: number): number[] {
  return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
}

function cborMap(entries: Array<[number[], number[]]>): number[] {
  return [...cborHead(5, entries.length), ...entries.flatMap(([key, value]) => [...key, ...value])];
}

/** A DER ECDSA signature, which is what an authenticator sends and what WebAuthn expects. */
function rawSignatureToDer(raw: Uint8Array): Uint8Array {
  const toInteger = (value: Uint8Array): number[] => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start += 1;
    const trimmed = [...value.subarray(start)];
    if ((trimmed[0]! & 0x80) !== 0) trimmed.unshift(0);
    return [0x02, trimmed.length, ...trimmed];
  };
  const r = toInteger(raw.subarray(0, 32));
  const s = toInteger(raw.subarray(32));
  const body = [...r, ...s];
  return new Uint8Array([0x30, body.length, ...body]);
}

export interface Authenticator {
  privateKey: CryptoKey;
  credentialId: Uint8Array;
  credentialIdText: string;
  coseKey: Uint8Array;
}

/** A software authenticator: real P-256 keys, real CBOR, real signatures, no browser. */
export async function newAuthenticator(): Promise<Authenticator> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
  const x = b64urlToBytes(jwk.x!);
  const y = b64urlToBytes(jwk.y!);
  const credentialId = crypto.getRandomValues(new Uint8Array(16));
  const coseKey = new Uint8Array(
    cborMap([
      [cborInt(1), cborInt(2)], // kty: EC2
      [cborInt(3), cborInt(-7)], // alg: ES256
      [cborInt(-1), cborInt(1)], // crv: P-256
      [cborInt(-2), cborBytes(x)],
      [cborInt(-3), cborBytes(y)],
    ]),
  );
  return { privateKey: pair.privateKey, credentialId, credentialIdText: b64urlEncode(credentialId), coseKey };
}

function b64urlToBytes(text: string): Uint8Array {
  const normalized = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

export async function registrationResponse(
  authenticator: Authenticator,
  challenge: string,
  overrides: { origin?: string; rpId?: string; counter?: number; extensionResults?: unknown } = {},
): Promise<Record<string, unknown>> {
  const origin = overrides.origin ?? DEFAULT_ORIGIN;
  const rpId = overrides.rpId ?? DEFAULT_RP_ID;
  const counter = overrides.counter ?? 0;
  const clientDataJSON = b64urlEncode(
    enc.encode(JSON.stringify({ type: 'webauthn.create', challenge, origin, crossOrigin: false })),
  );
  const authData = concat(
    await sha256(enc.encode(rpId)),
    new Uint8Array([0x45]), // UP | UV | AT
    be32(counter),
    new Uint8Array(16), // AAGUID
    be16(authenticator.credentialId.length),
    authenticator.credentialId,
    authenticator.coseKey,
  );
  const attestationObject = b64urlEncode(
    new Uint8Array(
      cborMap([
        [cborText('fmt'), cborText('none')],
        [cborText('attStmt'), cborMap([])],
        [cborText('authData'), cborBytes(authData)],
      ]),
    ),
  );

  return {
    id: authenticator.credentialIdText,
    rawId: authenticator.credentialIdText,
    type: 'public-key',
    clientExtensionResults: overrides.extensionResults ?? { credProps: { rk: true } },
    response: { clientDataJSON, attestationObject, transports: ['internal', 'hybrid'] },
  };
}

export async function assertionResponse(
  authenticator: Authenticator,
  challenge: string,
  overrides: { origin?: string; rpId?: string; counter?: number; userHandle?: string | null } = {},
): Promise<Record<string, unknown>> {
  const origin = overrides.origin ?? DEFAULT_ORIGIN;
  const rpId = overrides.rpId ?? DEFAULT_RP_ID;
  const counter = overrides.counter ?? 1;
  const clientDataBytes = enc.encode(
    JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }),
  );
  const authData = concat(await sha256(enc.encode(rpId)), new Uint8Array([0x05]), be32(counter));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      authenticator.privateKey,
      concat(authData, await sha256(clientDataBytes)),
    ),
  );

  return {
    id: authenticator.credentialIdText,
    rawId: authenticator.credentialIdText,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: b64urlEncode(clientDataBytes),
      authenticatorData: b64urlEncode(authData),
      signature: b64urlEncode(rawSignatureToDer(signature)),
      ...(overrides.userHandle === undefined ? {} : { userHandle: overrides.userHandle }),
    },
  };
}

