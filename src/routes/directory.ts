import { authenticateAccessToken } from '../auth';
import { randomHex, sha256Hex } from '../crypto/tokens';
import { CORS_HEADERS, errorResponse, jsonResponse } from '../http/response';
import type { DirectoryStore } from '../stores';
import type { AdminDeps } from './admin';

/** The opaque directory token: `am_uid_` plus 32 random bytes as hex. */
export const DIRECTORY_TOKEN_PREFIX = 'am_uid_';
export const DIRECTORY_TOKEN_LENGTH = 71;

export interface DirectoryDeps extends AdminDeps {
  directoryStore: DirectoryStore;
}

async function requireAdmin(request: Request, deps: DirectoryDeps): Promise<Response | null> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');
  if (!(await deps.userStore.isAdmin(auth.userId))) return errorResponse(403, 'admin_required');
  return null;
}

/** GET/POST/DELETE /admin/user-directory-token — admin only, never cached. */
export async function handleUserDirectoryToken(request: Request, deps: DirectoryDeps): Promise<Response> {
  const denied = await requireAdmin(request, deps);
  if (denied) return denied;

  const noStore = { 'cache-control': 'no-store' };

  if (request.method === 'GET') {
    const status = await deps.directoryStore.tokenStatus();
    return jsonResponse({ configured: status.configured, created_at: status.createdAt }, 200, noStore);
  }

  if (request.method === 'POST') {
    const token = `${DIRECTORY_TOKEN_PREFIX}${randomHex(32)}`;
    await deps.directoryStore.rotateToken(await sha256Hex(token));
    // The plaintext is returned once, on rotation, and never again.
    return jsonResponse({ token }, 201, noStore);
  }

  if (request.method === 'DELETE') {
    await deps.directoryStore.clearToken();
    return new Response(null, { status: 204, headers: { ...CORS_HEADERS, ...noStore } });
  }

  return errorResponse(405, 'method_not_allowed');
}

/** GET /integration/user-ids — server-to-server, directory token only, no CORS. */
export async function handleIntegrationUserIds(request: Request, deps: DirectoryDeps): Promise<Response> {
  const header = request.headers.get('authorization');
  const presented = header && /^Bearer (.+)$/i.test(header.trim()) ? /^Bearer (.+)$/i.exec(header.trim())![1]! : null;

  let authorised = false;
  if (presented && presented.length === DIRECTORY_TOKEN_LENGTH && presented.startsWith(DIRECTORY_TOKEN_PREFIX)) {
    authorised = await deps.directoryStore.matchesTokenHash(await sha256Hex(presented));
  }

  // No CORS headers on purpose: this endpoint is for server-to-server calls, and the spec says so.
  const headers = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
  if (!authorised) {
    return new Response(JSON.stringify({ error: 'invalid_directory_token' }), { status: 401, headers });
  }
  const userIds = await deps.directoryStore.listUserIds();
  return new Response(JSON.stringify({ user_ids: userIds }), { status: 200, headers });
}

/** GET /admin/users — users with credential and session counts. */
export async function handleAdminUsers(request: Request, deps: DirectoryDeps): Promise<Response> {
  const denied = await requireAdmin(request, deps);
  if (denied) return denied;

  const rows = await deps.directoryStore.listUsers(deps.now.toISOString());
  return jsonResponse({
    users: rows.map((row) => ({
      id: row.id,
      email: row.email,
      email_verified_at: row.emailVerifiedAt,
      created_at: row.createdAt,
      active_session_count: row.activeSessionCount,
      passkey_count: row.passkeyCount,
      ed25519_count: row.ed25519Count,
    })),
  });
}
