import type { Env } from './env';
import { ApiError, errorResponse, preflight } from './http/response';
import { StrictJsonError } from './http/strict-json';
import { handleJwks } from './routes/jwks';

type Handler = (request: Request, env: Env) => Promise<Response>;

/**
 * Route table keyed by "METHOD /path". The legacy server dispatches on the same pair,
 * so the table stays the single place where contract coverage is visible.
 */
const routes = new Map<string, Handler>([['GET /jwks', handleJwks]]);

export function routeKeys(): string[] {
  return [...routes.keys()].sort();
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') return preflight();

    const { pathname } = new URL(request.url);
    const handler = routes.get(`${request.method} ${pathname}`);
    if (!handler) return errorResponse(404, 'not_found');

    try {
      return await handler(request, env);
    } catch (error) {
      if (error instanceof ApiError) return errorResponse(error.status, error.code);
      if (error instanceof StrictJsonError) return errorResponse(400, error.message);
      console.error('unhandled_error', error instanceof Error ? error.message : 'unknown');
      return errorResponse(500, 'internal_error');
    }
  },
};
