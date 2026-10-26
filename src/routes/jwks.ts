import { D1SigningKeyStore } from '../d1-store';
import type { Env } from '../env';
import { jsonResponse } from '../http/response';
import { publicJwksBody } from '../jwks';

export async function handleJwks(_request: Request, env: Env): Promise<Response> {
  const body = await publicJwksBody(new D1SigningKeyStore(env.DB));
  return jsonResponse(body, 200, { 'cache-control': 'no-store' });
}
