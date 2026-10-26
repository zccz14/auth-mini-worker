import { describe, expect, it } from 'vitest';
import { b64urlDecodeText } from '../src/crypto/b64url';
import { generateKeyPair } from '../src/crypto/ed25519';
import { audienceJson, buildAccessTokenClaims, signAccessToken, verifyAccessToken } from '../src/jwt';

const baseInput = {
  userId: '031a393d-8a0a-4ca0-8cb1-313e0d71dfa9',
  sessionId: '6f1d0a2e-1111-4222-8333-444455556666',
  issuer: 'https://auth.ntnl.io',
  audiences: ['linkit.ntnl.io'],
  authenticationMethods: ['email_otp'],
  authAdmin: false,
  nowSeconds: 1_790_000_000,
  lifetimeSeconds: 900,
};

describe('access tokens', () => {
  it('signs and verifies a full round trip', async () => {
    const pair = await generateKeyPair();
    const claims = buildAccessTokenClaims(baseInput);
    const token = await signAccessToken({ kid: 'kid-a', privateJwk: pair.privateJwk }, claims);
    const verified = await verifyAccessToken({ kid: 'kid-a', publicJwk: pair.publicJwk }, token, baseInput.nowSeconds);

    expect(verified).toEqual(claims);
    expect(verified?.exp).toBe(baseInput.nowSeconds + 900);
  });

  it('keeps the legacy header and claim layout', async () => {
    const pair = await generateKeyPair();
    const claims = buildAccessTokenClaims(baseInput);
    const token = await signAccessToken({ kid: 'kid-a', privateJwk: pair.privateJwk }, claims);
    const [header, payload] = token.split('.') as [string, string];

    expect(JSON.parse(b64urlDecodeText(header))).toEqual({ alg: 'EdDSA', kid: 'kid-a', typ: 'JWT' });
    expect(Object.keys(JSON.parse(b64urlDecodeText(payload)))).toEqual([
      'sub',
      'sid',
      'iss',
      'aud',
      'amr',
      'auth_admin',
      'typ',
      'iat',
      'exp',
    ]);
  });

  it('serializes a single audience as a string and several as an array', async () => {
    expect(audienceJson(['a.example'])).toBe('a.example');
    expect(audienceJson(['a.example', 'b.example'])).toEqual(['a.example', 'b.example']);
    expect(audienceJson(['a.example', 'a.example'])).toBe('a.example');
    expect(() => audienceJson([])).toThrow('audience_required');
  });

  it('refuses tampered, mis-kid, expired and foreign-typ tokens', async () => {
    const pair = await generateKeyPair();
    const other = await generateKeyPair();
    const claims = buildAccessTokenClaims(baseInput);
    const token = await signAccessToken({ kid: 'kid-a', privateJwk: pair.privateJwk }, claims);
    const [header, , signature] = token.split('.') as [string, string, string];
    const forgedPayload = btoa(JSON.stringify({ ...claims, auth_admin: true })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    expect(await verifyAccessToken({ kid: 'kid-a', publicJwk: pair.publicJwk }, `${header}.${forgedPayload}.${signature}`, baseInput.nowSeconds)).toBeNull();
    expect(await verifyAccessToken({ kid: 'kid-b', publicJwk: pair.publicJwk }, token, baseInput.nowSeconds)).toBeNull();
    expect(await verifyAccessToken({ kid: 'kid-a', publicJwk: other.publicJwk }, token, baseInput.nowSeconds)).toBeNull();
    expect(await verifyAccessToken({ kid: 'kid-a', publicJwk: pair.publicJwk }, token, baseInput.nowSeconds + 901)).toBeNull();
    expect(await verifyAccessToken({ kid: 'kid-a', publicJwk: pair.publicJwk }, 'not-a-jwt', baseInput.nowSeconds)).toBeNull();
  });
});
