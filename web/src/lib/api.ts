/** The GUI is served by the same Worker, so the API base is this origin unless told otherwise. */
export function apiBase(): string {
  const configured = import.meta.env['VITE_API_BASE'];
  if (typeof configured === 'string' && configured.length > 0) return configured.replace(/\/$/, '');
  return new URL('..', window.location.href).origin;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
    this.name = 'ApiError';
  }
}

export async function api(path: string, init: RequestInit = {}): Promise<unknown> {
  const response = await fetch(`${apiBase()}${path}`, {
    ...init,
    headers: {
      ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(init.headers ?? {}),
    },
  });
  const text = await response.text();
  const body: unknown = text === '' ? null : JSON.parse(text);
  if (!response.ok) {
    const code =
      typeof body === 'object' && body !== null && 'error' in body ? String((body as { error: unknown }).error) : 'unknown_error';
    throw new ApiError(response.status, code);
  }
  return body;
}

export interface TokenPair {
  session_id: string;
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
}

export function isTokenPair(value: unknown): value is TokenPair {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record['session_id'] === 'string' &&
    typeof record['access_token'] === 'string' &&
    typeof record['refresh_token'] === 'string' &&
    typeof record['expires_in'] === 'number'
  );
}
