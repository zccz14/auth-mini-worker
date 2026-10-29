import type { AuthMiniApi } from 'auth-mini/sdk/browser';
import type { MeResponse } from 'auth-mini/sdk/api';
import { setupTokenHeaders } from '@/lib/setup-token';

type Ed25519Api = {
  register(input: { name: string; public_key: string }): Promise<unknown>;
  start(input: { public_key: string }): Promise<{
    request_id: string;
    challenge: string;
  }>;
  verify(input: {
    request_id: string;
    signature: string;
    redirect_uri?: string;
    aud?: string;
  }): Promise<AppSessionTokens>;
};

/**
 * The public face of the instance: what an unauthenticated visitor sees in the tab title, the
 * login page and the console header. Served by `GET /branding`, which needs no session.
 */
export type Branding = {
  issuer: string;
  rp_id: string;
  brand_name: string;
  brand_background_image: string;
};

export type AdminMailTemplate = {
  /** `{brand}`, `{code}` and `{minutes}` are substituted when the mail is sent. */
  subject: string;
  text: string;
};

export type AdminMailTemplates = {
  login: AdminMailTemplate;
  email_change: AdminMailTemplate;
};

/**
 * `/admin/setup` answers with the first-run projection only; `admin_ed25519`, `smtp` and
 * `mail_templates` come from `/admin/config`, which needs a token, so they are optional here
 * rather than absent by accident.
 */
export type AdminSetupState = {
  issuer: string;
  rp_id: string;
  brand_name: string;
  brand_background_image: string;
  admin_user_id: string | null;
  admin_ed25519?: unknown | null;
  mail_templates?: AdminMailTemplates;
  smtp?: null | Array<{
    id: number;
    host: string;
    port: number;
    username: string;
    from_email: string;
    from_name: string;
    secure: boolean;
    is_active: boolean;
    weight: number;
  }>;
};

export type AdminConfigInput = {
  issuer: string;
  rp_id: string;
  brand_name: string;
  brand_background_image: string;
  mail_templates: AdminMailTemplates;
  smtp: null | Array<{
    id: number | null;
    host: string;
    port: number;
    username: string;
    password: string;
    from_email: string;
    from_name: string;
    secure: boolean;
    weight: number;
  }>;
};

export type AdminJwkSlot = {
  slot: 'CURRENT' | 'STANDBY';
  public_jwk: Record<string, unknown>;
};

export type AdminJwksResponse = {
  keys: AdminJwkSlot[];
};

export type DirectoryTokenStatus = {
  configured: boolean;
  created_at: string | null;
};

export type AdminRequestAuditSnapshot = {
  /** Start of the counting window in Unix seconds — a fixed 24 h, not server uptime. */
  started_at: number;
  window_seconds: number;
  endpoints: Array<{
    method: string;
    endpoint: string;
    count: number;
    error_count: number;
    mean_ms: number;
  }>;
  unmatched: Array<{
    method: string;
    path: string;
    count: number;
    last_seen: number;
  }>;
};

type AdminApi = {
  directoryToken: {
    status(): Promise<DirectoryTokenStatus>;
    rotate(): Promise<{ token: string }>;
    revoke(): Promise<void>;
  };
  setup: {
    fetch(): Promise<AdminSetupState>;
    passkeyOptions(): Promise<SetupRegistrationOptions>;
    /** Claims the instance: the credential, then the administrator, in that order. */
    initialize(input: {
      request_id: string;
      credential: Record<string, unknown>;
      issuer: string;
      rp_id: string;
    }): Promise<{ ok: true }>;
  };
  config: {
    fetch(): Promise<AdminSetupState>;
    save(input: AdminConfigInput): Promise<AdminSetupState>;
  };
  jwks: {
    list(): Promise<AdminJwksResponse>;
    rotate(): Promise<AdminJwksResponse>;
  };
  requestAudit: {
    fetch(): Promise<AdminRequestAuditSnapshot>;
  };
  users(): Promise<{ users: Array<Record<string, unknown>> }>;
};

export type AppCurrentUser = MeResponse;

export type RemoteLoginStart = {
  request_id: string;
  exchange_code: string;
  confirmation_code: string;
  expires_at: string;
};

export type RemoteLoginRequest = {
  request_id: string;
  audiences: string[];
  expires_at: string;
};

type RemoteLoginApi = {
  start(input: {
    redirect_uri?: string;
    aud?: string;
    audiences?: string[];
  }): Promise<RemoteLoginStart>;
  exchange(input: {
    request_id: string;
    exchange_code: string;
  }): Promise<AppSessionTokens>;
  pending(): Promise<{ requests: RemoteLoginRequest[] }>;
  claim(input: { confirmation_code: string }): Promise<RemoteLoginRequest>;
  approve(requestId: string): Promise<{ ok: true }>;
  deny(requestId: string): Promise<{ ok: true }>;
};

type CurrentUserApi = {
  fetch(): Promise<AppCurrentUser>;
  email: {
    startChange(input: { email: string }): Promise<{ ok: true }>;
    verifyChange(input: { email: string; code: string }): Promise<{ ok: true }>;
  };
};

export type AppSdk = AuthMiniApi & {
  branding: { fetch(): Promise<Branding> };
  admin: AdminApi;
  currentUser: CurrentUserApi;
  remoteLogin: RemoteLoginApi;
  ed25519: Ed25519Api;
  authorizeSession(input: SessionAuthorizeInput): Promise<AppSessionTokens>;
};

export type SetupRegistrationOptions = {
  request_id: string;
  publicKey: import('@/lib/webauthn').RegistrationOptions;
};

export type AppSessionTokens = {
  session_id: string;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: 'Bearer';
};

export type SessionAuthorizeInput = {
  redirect_uri?: string;
  aud?: string;
  audiences?: string[];
};

export function extendAppSdk(sdk: AuthMiniApi, serverBaseUrl: string): AppSdk {
  function isRetryableAuthError(error: unknown): boolean {
    return (
      typeof error === 'object' &&
      error !== null &&
      'status' in error &&
      error.status === 401 &&
      (!('error' in error) || error.error !== 'session_superseded')
    );
  }

  async function requireAccessToken(forceRefresh = false): Promise<string> {
    const snapshot = sdk.session.getState();

    if (!snapshot.refreshToken && !snapshot.accessToken) {
      throw new Error('Missing authenticated session');
    }

    if (!forceRefresh && snapshot.accessToken) {
      return snapshot.accessToken;
    }

    const refreshed = await sdk.session.refresh();

    if (!refreshed.accessToken) {
      throw new Error('Missing authenticated session');
    }

    return refreshed.accessToken;
  }

  async function postJson<T>(
    path: string,
    body: unknown,
    accessToken?: string | null,
    extraHeaders: Record<string, string> = {},
  ) {
    const response = await fetch(new URL(path, serverBaseUrl), {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
        ...extraHeaders,
      },
      body: JSON.stringify(body),
    });

    const payload = (await response.json()) as T | { error?: string };
    if (!response.ok) {
      if (typeof payload === 'object' && payload !== null) {
        throw { status: response.status, ...payload };
      }

      throw { status: response.status, error: 'request_failed' };
    }

    return payload as T;
  }

  async function getJson<T>(
    path: string,
    accessToken?: string | null,
    extraHeaders: Record<string, string> = {},
  ) {
    const response = await fetch(new URL(path, serverBaseUrl), {
      headers: {
        accept: 'application/json',
        ...(accessToken ? { authorization: 'Bearer ' + accessToken } : {}),
        ...extraHeaders,
      },
    });
    const payload = (await response.json()) as T | { error?: string };
    if (!response.ok) {
      throw { status: response.status, ...payload };
    }

    return payload as T;
  }

  async function putJson<T>(
    path: string,
    body: unknown,
    accessToken?: string | null,
    extraHeaders: Record<string, string> = {},
  ) {
    const response = await fetch(new URL(path, serverBaseUrl), {
      method: 'PUT',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        ...(accessToken ? { authorization: 'Bearer ' + accessToken } : {}),
        ...extraHeaders,
      },
      body: JSON.stringify(body),
    });
    const payload = (await response.json()) as T | { error?: string };
    if (!response.ok) {
      throw { status: response.status, ...payload };
    }

    return payload as T;
  }

  return {
    ...sdk,
    branding: {
      fetch() {
        return getJson<Branding>('/branding');
      },
    },
    async authorizeSession(input) {
      try {
        return await postJson<AppSessionTokens>(
          '/session/authorize',
          input,
          await requireAccessToken(),
        );
      } catch (error) {
        if (
          !isRetryableAuthError(error) ||
          !sdk.session.getState().refreshToken
        ) {
          throw error;
        }

        return await postJson<AppSessionTokens>(
          '/session/authorize',
          input,
          await requireAccessToken(true),
        );
      }
    },
    admin: {
      directoryToken: {
        async status() {
          return getJson<DirectoryTokenStatus>(
            '/admin/user-directory-token',
            await requireAccessToken(),
          );
        },
        async rotate() {
          return postJson<{ token: string }>(
            '/admin/user-directory-token',
            {},
            await requireAccessToken(),
          );
        },
        async revoke() {
          const response = await fetch(
            new URL('/admin/user-directory-token', serverBaseUrl),
            {
              method: 'DELETE',
              headers: {
                authorization: `Bearer ${await requireAccessToken()}`,
              },
            },
          );
          if (!response.ok)
            throw new Error(`Request failed (${response.status})`);
        },
      },
      setup: {
        fetch() {
          return getJson<AdminSetupState>('/admin/setup', null, setupTokenHeaders());
        },
        passkeyOptions() {
          return postJson<SetupRegistrationOptions>(
            '/admin/setup/passkey/options',
            {},
            null,
            setupTokenHeaders(),
          );
        },
        initialize(input) {
          return putJson<{ ok: true }>(
            '/admin/setup',
            input,
            null,
            setupTokenHeaders(),
          );
        },
      },
      config: {
        async fetch() {
          return getJson<AdminSetupState>(
            '/admin/config',
            await requireAccessToken(),
          );
        },
        async save(input) {
          return putJson<AdminSetupState>(
            '/admin/config',
            input,
            await requireAccessToken(),
          );
        },
      },
      jwks: {
        async list() {
          return getJson<AdminJwksResponse>(
            '/admin/jwks',
            await requireAccessToken(),
          );
        },
        async rotate() {
          return postJson<AdminJwksResponse>(
            '/admin/jwks/rotate',
            {},
            await requireAccessToken(),
          );
        },
      },
      requestAudit: {
        async fetch() {
          return getJson<AdminRequestAuditSnapshot>(
            '/admin/request-audit',
            await requireAccessToken(),
          );
        },
      },
      async users() {
        return getJson<{ users: Array<Record<string, unknown>> }>(
          '/admin/users',
          await requireAccessToken(),
        );
      },
    },
    currentUser: {
      async fetch() {
        const accessToken = await requireAccessToken();

        try {
          return await getJson<AppCurrentUser>('/me', accessToken);
        } catch (error) {
          if (
            !isRetryableAuthError(error) ||
            !sdk.session.getState().refreshToken
          ) {
            throw error;
          }

          return await getJson<AppCurrentUser>(
            '/me',
            await requireAccessToken(true),
          );
        }
      },
      email: {
        async startChange(input) {
          try {
            return await postJson<{ ok: true }>(
              '/me/email/start',
              input,
              await requireAccessToken(),
            );
          } catch (error) {
            if (
              !isRetryableAuthError(error) ||
              !sdk.session.getState().refreshToken
            ) {
              throw error;
            }

            return await postJson<{ ok: true }>(
              '/me/email/start',
              input,
              await requireAccessToken(true),
            );
          }
        },
        async verifyChange(input) {
          try {
            return await postJson<{ ok: true }>(
              '/me/email/verify',
              input,
              await requireAccessToken(),
            );
          } catch (error) {
            if (
              !isRetryableAuthError(error) ||
              !sdk.session.getState().refreshToken
            ) {
              throw error;
            }

            return await postJson<{ ok: true }>(
              '/me/email/verify',
              input,
              await requireAccessToken(true),
            );
          }
        },
      },
    },
    remoteLogin: {
      start(input) {
        return postJson<RemoteLoginStart>('/remote-login/start', input);
      },
      exchange(input) {
        return postJson<AppSessionTokens>(
          `/remote-login/${input.request_id}/exchange`,
          input,
        );
      },
      async pending() {
        return getJson<{ requests: RemoteLoginRequest[] }>(
          '/remote-login/pending',
          await requireAccessToken(),
        );
      },
      async claim(input) {
        return postJson<RemoteLoginRequest>(
          '/remote-login/claim',
          input,
          await requireAccessToken(),
        );
      },
      async approve(requestId) {
        return postJson<{ ok: true }>(
          `/remote-login/${requestId}/approve`,
          {},
          await requireAccessToken(),
        );
      },
      async deny(requestId) {
        return postJson<{ ok: true }>(
          `/remote-login/${requestId}/deny`,
          {},
          await requireAccessToken(),
        );
      },
    },
    ed25519: {
      async register(input: { name: string; public_key: string }) {
        const requestBody = {
          name: input.name,
          public_key: input.public_key,
        };

        try {
          return await postJson(
            '/ed25519/credentials',
            requestBody,
            await requireAccessToken(),
          );
        } catch (error) {
          if (
            !isRetryableAuthError(error) ||
            !sdk.session.getState().refreshToken
          ) {
            throw error;
          }

          return await postJson(
            '/ed25519/credentials',
            requestBody,
            await requireAccessToken(true),
          );
        }
      },
      start(input: { public_key: string }) {
        return postJson<{ request_id: string; challenge: string }>(
          '/ed25519/start',
          input,
        );
      },
      verify(input: { request_id: string; signature: string }) {
        return postJson<AppSessionTokens>('/ed25519/verify', input);
      },
    },
  };
}
