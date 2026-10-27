const STORAGE_KEY = 'auth-mini.gui.setup-token';

/**
 * The shared secret that opens the first-run window (`ADMIN_SETUP_TOKEN`).
 *
 * It lives in `sessionStorage`: a claim is one sitting, and a token left behind in
 * `localStorage` would outlive the window it protects. Nothing else reads it, so a blocked
 * storage only costs the user one extra paste.
 */
export function readSetupToken(): string {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}

export function writeSetupToken(token: string): void {
  try {
    if (token.trim().length === 0) window.sessionStorage.removeItem(STORAGE_KEY);
    else window.sessionStorage.setItem(STORAGE_KEY, token.trim());
  } catch {
    // Storage can be blocked; the token then simply is not remembered.
  }
}

/** Empty when no token is configured, so the header is omitted rather than sent blank. */
export function setupTokenHeaders(): Record<string, string> {
  const token = readSetupToken().trim();
  return token.length === 0 ? {} : { 'x-admin-setup-token': token };
}
