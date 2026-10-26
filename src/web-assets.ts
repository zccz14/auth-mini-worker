import type { Env } from './env';
import { errorResponse } from './http/response';

/**
 * The GUI is a hash-routed SPA served under `/web/`, the same path the legacy server used, so
 * existing login links keep working. Everything is served by the Worker on purpose
 * (`run_worker_first`): the API must keep answering 404 for unknown paths instead of being caught
 * by an SPA fallback.
 */
const PREFIX = '/web/';

export function isWebAssetPath(pathname: string): boolean {
  return pathname === '/web' || pathname.startsWith(PREFIX);
}

export async function serveWebAsset(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === '/web') {
    // Relative asset URLs only resolve correctly with the trailing slash.
    return Response.redirect(`${url.origin}${PREFIX}`, 308);
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return errorResponse(405, 'method_not_allowed');
  }

  const rest = url.pathname.slice(PREFIX.length);
  const isHashedAsset = rest.startsWith('assets/');

  // Vite emits content-hashed names, so anything under assets/ can be cached forever; the shell
  // must not be, or a deploy would keep serving the old bundle.
  const target = isHashedAsset ? new URL(`/${rest}`, url.origin) : new URL('/index.html', url.origin);
  const asset = await env.ASSETS.fetch(new Request(target, { method: request.method }));
  if (asset.status === 404) return errorResponse(404, 'not_found');

  const headers = new Headers(asset.headers);
  headers.set('cache-control', isHashedAsset ? 'public, max-age=31536000, immutable' : 'no-cache');
  headers.set('x-content-type-options', 'nosniff');
  return new Response(request.method === 'HEAD' ? null : asset.body, { status: asset.status, headers });
}
