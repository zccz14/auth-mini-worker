import { api, isTokenPair, type TokenPair } from './api';

/** One main-site session per browser, kept in local storage so it survives a reload. */
export interface StoredSession {
  sessionId: string;
  accessToken: string;
  refreshToken: string;
  /** Epoch milliseconds; the access token lives 900 s but we refresh well before that. */
  expiresAt: number;
  email: string | null;
}

const STORAGE_KEY = 'auth-mini.session.v1';
const REFRESH_AHEAD_MS = 60_000;

export function loadSession(): StoredSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === null) return null;
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return null;
    const record = parsed as Record<string, unknown>;
    if (
      typeof record['sessionId'] !== 'string' ||
      typeof record['accessToken'] !== 'string' ||
      typeof record['refreshToken'] !== 'string' ||
      typeof record['expiresAt'] !== 'number'
    ) {
      return null;
    }
    return {
      sessionId: record['sessionId'],
      accessToken: record['accessToken'],
      refreshToken: record['refreshToken'],
      expiresAt: record['expiresAt'],
      email: typeof record['email'] === 'string' ? record['email'] : null,
    };
  } catch {
    return null;
  }
}

export function saveTokens(tokens: TokenPair, email: string | null): StoredSession {
  const session: StoredSession = {
    sessionId: tokens.session_id,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: Date.now() + tokens.expires_in * 1000,
    email,
  };
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
  } catch {
    // A browser that refuses storage still works for this page view.
  }
  return session;
}

export function clearSession(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore: nothing to clear if storage is unavailable.
  }
}

/**
 * Refresh tokens rotate on every use, so two tabs refreshing at once would invalidate each other.
 * The Web Locks API serialises them, and the loser of the race re-reads storage instead of sending
 * a second request.
 */
export async function freshSession(session: StoredSession): Promise<StoredSession | null> {
  if (session.expiresAt - Date.now() > REFRESH_AHEAD_MS) return session;
  if (typeof navigator !== 'undefined' && 'locks' in navigator) {
    return navigator.locks.request('auth-mini.refresh', async () => {
      const current = loadSession();
      if (current === null) return null;
      if (current.expiresAt - Date.now() > REFRESH_AHEAD_MS) return current;
      return refresh(current);
    });
  }
  return refresh(session);
}

async function refresh(session: StoredSession): Promise<StoredSession | null> {
  try {
    const body = await api('/session/refresh', {
      method: 'POST',
      body: JSON.stringify({ session_id: session.sessionId, refresh_token: session.refreshToken }),
    });
    if (!isTokenPair(body)) return null;
    return saveTokens(body, session.email);
  } catch {
    clearSession();
    return null;
  }
}
