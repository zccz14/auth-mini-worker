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

  // Vite emits content-hashed bundles under assets/ plus a handful of stable files (the shell,
  // the brand icons). Both are real files on the edge, so look the path up before deciding.
  const rest = url.pathname.slice(PREFIX.length);
  const asset = await env.ASSETS.fetch(
    new Request(new URL(`/${rest || 'index.html'}`, url.origin), { method: request.method }),
  );

  if (asset.status === 404) {
    // A missing file is a broken reference, not a route: answering with the shell would make the
    // browser parse HTML as JavaScript. Anything without an extension is a deep link, which the
    // hash router handles client-side.
    const lastSegment = rest.slice(rest.lastIndexOf('/') + 1);
    if (lastSegment.includes('.')) return errorResponse(404, 'not_found');

    const shell = await env.ASSETS.fetch(
      new Request(new URL('/index.html', url.origin), { method: request.method }),
    );
    return withHeaders(shell, request, false);
  }

  return withHeaders(asset, request, rest.startsWith('assets/'));
}

function withHeaders(asset: Response, request: Request, isHashedAsset: boolean): Response {
  const headers = new Headers(asset.headers);
  // Content-hashed names can be cached forever; everything else, the shell included, must not be,
  // or a deploy would keep serving the old bundle.
  headers.set('cache-control', isHashedAsset ? 'public, max-age=31536000, immutable' : 'no-cache');
  headers.set('x-content-type-options', 'nosniff');
  return new Response(request.method === 'HEAD' ? null : asset.body, { status: asset.status, headers });
}
