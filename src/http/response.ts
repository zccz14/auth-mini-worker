export const CORS_HEADERS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS',
  'access-control-allow-headers': '*',
};

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(code);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export function jsonResponse(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    // Authorization state changes underneath a browser: /admin/setup flips from "uninitialized" to
    // "initialized" the moment an admin is claimed. A JSON body without an explicit policy may be
    // reused heuristically, which serves an old answer to a question whose whole point is freshness.
    // Callers that genuinely want caching (none today) can override it through extraHeaders.
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS_HEADERS, ...extraHeaders },
  });
}

export function errorResponse(status: number, code: string): Response {
  return jsonResponse({ error: code }, status);
}

export function preflight(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}
