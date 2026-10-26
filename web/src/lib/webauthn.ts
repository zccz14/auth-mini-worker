import { api, isTokenPair, type TokenPair } from './api';

function b64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function bytesToB64url(bytes: ArrayBuffer): string {
  const view = new Uint8Array(bytes);
  let binary = '';
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface CredentialDescriptorJson {
  id: string;
  type: string;
  transports?: string[];
}

interface RequestOptionsJson {
  challenge: string;
  rpId: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: CredentialDescriptorJson[];
}

function toCredentialJson(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    ...(credential.authenticatorAttachment === null ? {} : { authenticatorAttachment: credential.authenticatorAttachment }),
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: bytesToB64url(response.clientDataJSON),
      authenticatorData: bytesToB64url(response.authenticatorData),
      signature: bytesToB64url(response.signature),
      userHandle: response.userHandle === null ? null : bytesToB64url(response.userHandle),
    },
  };
}

/** One discoverable sign-in: options, the platform prompt, then the assertion. */
export async function passkeySignIn(): Promise<TokenPair> {
  const options = (await api('/webauthn/authenticate/options', { method: 'POST', body: '{}' })) as {
    request_id: string;
    publicKey: RequestOptionsJson;
  };

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: b64urlToBytes(options.publicKey.challenge),
    rpId: options.publicKey.rpId,
    ...(options.publicKey.timeout === undefined ? {} : { timeout: options.publicKey.timeout }),
    ...(options.publicKey.userVerification === undefined ? {} : { userVerification: options.publicKey.userVerification }),
    ...(options.publicKey.allowCredentials === undefined
      ? {}
      : {
          allowCredentials: options.publicKey.allowCredentials.map((entry) => ({
            id: b64urlToBytes(entry.id),
            type: entry.type as PublicKeyCredentialType,
            ...(entry.transports === undefined ? {} : { transports: entry.transports as AuthenticatorTransport[] }),
          })),
        }),
  };

  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (credential === null) throw new Error('passkey_cancelled');

  const body = await api('/webauthn/authenticate/verify', {
    method: 'POST',
    body: JSON.stringify({ request_id: options.request_id, credential: toCredentialJson(credential) }),
  });
  if (!isTokenPair(body)) throw new Error('invalid_token_response');
  return body;
}
