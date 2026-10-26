#!/usr/bin/env node
/**
 * End-to-end WebAuthn smoke test against a running instance.
 *
 * It plays the authenticator itself: real P-256 keys, real CBOR, real DER signatures, no browser.
 * Registration and assertion therefore exercise the server's verification path on whatever runtime
 * is behind `--base` — workerd included — which unit tests running in Node cannot prove.
 *
 *   node scripts/webauthn-smoke.mjs --base https://auth-mini-worker-smoke.example.workers.dev \
 *                                   --token <access token for a signed-in user> \
 *                                   [--origin http://localhost:7777]
 *
 * The caller owns the session: seeding one in D1 and refreshing it is a database operation, not
 * something this script should be able to do.
 */
const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    if (value.startsWith('--')) pairs.push([value.slice(2), all[index + 1]]);
    return pairs;
  }, []),
);

const BASE = (args.base ?? '').replace(/\/$/, '');
const TOKEN = args.token ?? '';
if (BASE === '' || TOKEN === '') {
  console.error('usage: webauthn-smoke.mjs --base <url> --token <access token>');
  process.exit(2);
}

const enc = new TextEncoder();

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const unb64url = (text) => new Uint8Array(Buffer.from(text, 'base64url'));

function be16(value) {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}

function be32(value) {
  return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

function cborHead(major, length) {
  if (length < 24) return [(major << 5) | length];
  if (length < 256) return [(major << 5) | 24, length];
  return [(major << 5) | 25, (length >> 8) & 0xff, length & 0xff];
}

const cborText = (value) => [...cborHead(3, enc.encode(value).length), ...enc.encode(value)];
const cborBytes = (value) => [...cborHead(2, value.length), ...value];
const cborInt = (value) => (value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value));
const cborMap = (entries) => [...cborHead(5, entries.length), ...entries.flatMap(([key, value]) => [...key, ...value])];

function rawSignatureToDer(raw) {
  const toInteger = (value) => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start += 1;
    const trimmed = [...value.subarray(start)];
    if ((trimmed[0] & 0x80) !== 0) trimmed.unshift(0);
    return [0x02, trimmed.length, ...trimmed];
  };
  const body = [...toInteger(raw.subarray(0, 32)), ...toInteger(raw.subarray(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}

async function call(path, body, { token, method = 'POST' } = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  return { status: response.status, body: text === '' ? null : JSON.parse(text) };
}

function fail(message, detail) {
  console.error(`FAIL ${message}`, detail ?? '');
  process.exit(1);
}

// The ceremony origin is the configured issuer, which need not be the URL the worker answers on
// (a local run against http://localhost:8787 still belongs to the http://localhost:7777 issuer).
const origin = args.origin ?? new URL(BASE).origin;
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
const credentialId = crypto.getRandomValues(new Uint8Array(16));
const credentialIdText = b64url(credentialId);
const coseKey = new Uint8Array(
  cborMap([
    [cborInt(1), cborInt(2)],
    [cborInt(3), cborInt(-7)],
    [cborInt(-1), cborInt(1)],
    [cborInt(-2), cborBytes(unb64url(jwk.x))],
    [cborInt(-3), cborBytes(unb64url(jwk.y))],
  ]),
);

// ---- registration -------------------------------------------------------------------------
const options = await call('/webauthn/register/options', {}, { token: TOKEN });
if (options.status !== 200) fail('register/options', options);
const { request_id: registerId, publicKey } = options.body;
if (publicKey.challenge.length !== 43) fail('challenge length', publicKey.challenge);

const createClientData = enc.encode(
  JSON.stringify({ type: 'webauthn.create', challenge: publicKey.challenge, origin, crossOrigin: false }),
);
const authData = concat(
  await sha256(enc.encode(publicKey.rp.id)),
  new Uint8Array([0x45]),
  be32(0),
  new Uint8Array(16),
  be16(credentialId.length),
  credentialId,
  coseKey,
);
const attestationObject = new Uint8Array(
  cborMap([
    [cborText('fmt'), cborText('none')],
    [cborText('attStmt'), cborMap([])],
    [cborText('authData'), cborBytes(authData)],
  ]),
);
const registration = await call(
  '/webauthn/register/verify',
  {
    request_id: registerId,
    credential: {
      id: credentialIdText,
      rawId: credentialIdText,
      type: 'public-key',
      clientExtensionResults: { credProps: { rk: true } },
      response: {
        clientDataJSON: b64url(createClientData),
        attestationObject: b64url(attestationObject),
        transports: ['internal', 'hybrid'],
      },
    },
  },
  { token: TOKEN },
);
if (registration.status !== 200) fail('register/verify', registration);
console.log('ok  register/verify', registration.body);

const replay = await call(
  '/webauthn/register/verify',
  {
    request_id: registerId,
    credential: {
      id: credentialIdText,
      rawId: credentialIdText,
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON: b64url(createClientData), attestationObject: b64url(attestationObject) },
    },
  },
  { token: TOKEN },
);
if (replay.status !== 400) fail('replayed registration should be refused', replay);
console.log('ok  replayed registration refused', replay.body);

// ---- authentication -----------------------------------------------------------------------
const login = await call('/webauthn/authenticate/options', {});
if (login.status !== 200) fail('authenticate/options', login);
if ('allowCredentials' in login.body.publicKey) fail('allowCredentials must be absent', login.body.publicKey);

const counter = 1;
const getClientData = enc.encode(
  JSON.stringify({ type: 'webauthn.get', challenge: login.body.publicKey.challenge, origin, crossOrigin: false }),
);
const assertionData = concat(
  await sha256(enc.encode(login.body.publicKey.rpId)),
  new Uint8Array([0x05]),
  be32(counter),
);
const signature = new Uint8Array(
  await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    pair.privateKey,
    concat(assertionData, await sha256(getClientData)),
  ),
);
const assertion = await call('/webauthn/authenticate/verify', {
  request_id: login.body.request_id,
  credential: {
    id: credentialIdText,
    rawId: credentialIdText,
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: b64url(getClientData),
      authenticatorData: b64url(assertionData),
      signature: b64url(rawSignatureToDer(signature)),
    },
  },
});
if (assertion.status !== 200) fail('authenticate/verify', assertion);
if (assertion.body.token_type !== 'Bearer' || assertion.body.refresh_token.length !== 64) {
  fail('token pair shape', assertion.body);
}
console.log('ok  authenticate/verify', {
  session_id: assertion.body.session_id,
  expires_in: assertion.body.expires_in,
});

// ---- the passkey is now visible on /me, with its transports --------------------------------
const me = await call('/me', undefined, { token: assertion.body.access_token, method: 'GET' });
if (me.status !== 200) fail('me', me);
const listed = me.body.webauthn_credentials.find((entry) => entry.credential_id === credentialIdText);
if (!listed) fail('credential missing from /me', me.body.webauthn_credentials);
if (JSON.stringify(listed.transports) !== JSON.stringify(['internal', 'hybrid'])) fail('transports', listed);
console.log('ok  /me lists the credential', listed);

// ---- teardown -----------------------------------------------------------------------------
const deleted = await call(`/webauthn/credentials/${credentialIdText}`, undefined, { token: TOKEN, method: 'DELETE' });
if (deleted.status !== 200) fail('delete', deleted);
console.log('ok  delete', deleted.body);
