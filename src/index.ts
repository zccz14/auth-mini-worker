import { D1AdminStore } from './d1-admin';
import { D1SigningKeyStore } from './d1-store';
import {
  D1AppMetaStore,
  D1CredentialStore,
  D1EmailOtpStore,
  D1SessionStore,
  D1SmtpConfigStore,
  D1UserStore,
} from './d1-stores';
import type { Env } from './env';
import { ApiError, errorResponse, preflight } from './http/response';
import { StrictJsonError } from './http/strict-json';
import { buildMimeMessage } from './mail/message';
import { sendSmtpMail, workerSocketFactory } from './mail/smtp';
import type { EmailDeps } from './routes/email';
import { handleEmailStart, handleEmailVerify } from './routes/email';
import { D1Ed25519Store } from './d1-ed25519';
import { D1RemoteLoginStore } from './d1-remote-login';
import type { AdminDeps } from './routes/admin';
import type { RemoteLoginDeps } from './routes/remote-login';
import {
  handleRemoteLoginApprove,
  handleRemoteLoginClaim,
  handleRemoteLoginDeny,
  handleRemoteLoginExchange,
  handleRemoteLoginPending,
  handleRemoteLoginStart,
  handleSessionAuthorize,
} from './routes/remote-login';
import type { Ed25519Deps } from './routes/ed25519';
import {
  handleEd25519CredentialCreate,
  handleEd25519CredentialDelete,
  handleEd25519CredentialUpdate,
  handleEd25519CredentialsList,
  handleEd25519Start,
  handleEd25519Verify,
} from './routes/ed25519';
import { handleAdminConfig, handleAdminJwks, handleAdminJwksRotate, handleAdminSetup } from './routes/admin';
import type { SessionDeps } from './routes/session';
import { handleMe, handleSessionLogout, handleSessionRefresh, handleTime } from './routes/session';
import { handleJwks } from './routes/jwks';

async function emailDeps(request: Request, env: Env): Promise<EmailDeps> {
  return {
    issuer: await new D1AppMetaStore(env.DB).readIssuer(),
    otpStore: new D1EmailOtpStore(env.DB),
    userStore: new D1UserStore(env.DB),
    sessionStore: new D1SessionStore(env.DB),
    keyStore: new D1SigningKeyStore(env.DB),
    smtpStore: new D1SmtpConfigStore(env.DB),
    sendMail: async (config, to, content) => {
      const raw = buildMimeMessage(config, to, content, new Date());
      await sendSmtpMail(
        workerSocketFactory,
        {
          host: config.host,
          port: config.port,
          username: config.username,
          password: config.password,
          secure: config.secure,
        },
        { from: config.fromEmail, to, raw },
        { timeoutMs: 15_000 },
      );
    },
    now: new Date(),
    clientIp: request.headers.get('cf-connecting-ip'),
    userAgent: request.headers.get('user-agent'),
  };
}

async function sessionDeps(_request: Request, env: Env): Promise<SessionDeps> {
  return {
    issuer: await new D1AppMetaStore(env.DB).readIssuer(),
    keyStore: new D1SigningKeyStore(env.DB),
    sessionStore: new D1SessionStore(env.DB),
    userStore: new D1UserStore(env.DB),
    credentialStore: new D1CredentialStore(env.DB),
    now: new Date(),
  };
}

async function ed25519Deps(request: Request, env: Env): Promise<Ed25519Deps> {
  return {
    ...(await sessionDeps(request, env)),
    ed25519Store: new D1Ed25519Store(env.DB),
    clientIp: request.headers.get('cf-connecting-ip'),
    userAgent: request.headers.get('user-agent'),
  };
}

async function remoteLoginDeps(request: Request, env: Env): Promise<RemoteLoginDeps> {
  return {
    ...(await sessionDeps(request, env)),
    remoteLoginStore: new D1RemoteLoginStore(env.DB),
    clientIp: request.headers.get('cf-connecting-ip'),
    userAgent: request.headers.get('user-agent'),
  };
}

async function adminDeps(request: Request, env: Env): Promise<AdminDeps> {
  return {
    ...(await sessionDeps(request, env)),
    adminStore: new D1AdminStore(env.DB),
    setupToken: env.ADMIN_SETUP_TOKEN ?? null,
  };
}

type Params = Record<string, string>;
type ParamsHandler = (request: Request, env: Env, params: Params) => Promise<Response>;

interface Route {
  method: string;
  /** Segments after the leading slash; `:name` captures one segment. */
  segments: string[];
  handler: ParamsHandler;
}

function route(method: string, path: string, handler: ParamsHandler): Route {
  return { method, segments: path.split('/').filter((segment) => segment.length > 0), handler };
}

/**
 * Route table. The legacy server dispatches on (method, path), so this table stays the single
 * place where contract coverage is visible.
 */
const routes: Route[] = [
  route('GET', '/jwks', (request, env) => handleJwks(request, env)),
  route('POST', '/email/start', async (request, env) => handleEmailStart(request, await emailDeps(request, env))),
  route('POST', '/email/verify', async (request, env) => handleEmailVerify(request, await emailDeps(request, env))),
  route('POST', '/session/refresh', async (request, env) => handleSessionRefresh(request, await sessionDeps(request, env))),
  route('POST', '/session/logout', async (request, env) => handleSessionLogout(request, await sessionDeps(request, env))),
  route('GET', '/me', async (request, env) => handleMe(request, await sessionDeps(request, env))),
  route('GET', '/time', async () => handleTime(new Date())),
  route('GET', '/admin/setup', async (request, env) => handleAdminSetup(request, await adminDeps(request, env))),
  route('PUT', '/admin/setup', async (request, env) => handleAdminSetup(request, await adminDeps(request, env))),
  route('GET', '/admin/config', async (request, env) => handleAdminConfig(request, await adminDeps(request, env))),
  route('PUT', '/admin/config', async (request, env) => handleAdminConfig(request, await adminDeps(request, env))),
  route('GET', '/admin/jwks', async (request, env) => handleAdminJwks(request, await adminDeps(request, env))),
  route('POST', '/admin/jwks/rotate', async (request, env) => handleAdminJwksRotate(request, await adminDeps(request, env))),
  route('POST', '/ed25519/start', async (request, env) => handleEd25519Start(request, await ed25519Deps(request, env))),
  route('POST', '/ed25519/verify', async (request, env) => handleEd25519Verify(request, await ed25519Deps(request, env))),
  route('GET', '/ed25519/credentials', async (request, env) => handleEd25519CredentialsList(request, await ed25519Deps(request, env))),
  route('POST', '/ed25519/credentials', async (request, env) => handleEd25519CredentialCreate(request, await ed25519Deps(request, env))),
  route('POST', '/session/authorize', async (request, env) => handleSessionAuthorize(request, await sessionDeps(request, env))),
  route('POST', '/remote-login/start', async (request, env) => handleRemoteLoginStart(request, await remoteLoginDeps(request, env))),
  route('GET', '/remote-login/pending', async (request, env) => handleRemoteLoginPending(request, await remoteLoginDeps(request, env))),
  route('POST', '/remote-login/claim', async (request, env) => handleRemoteLoginClaim(request, await remoteLoginDeps(request, env))),
  route('POST', '/remote-login/:id/approve', async (request, env, params) =>
    handleRemoteLoginApprove(request, await remoteLoginDeps(request, env), params['id'] ?? ''),
  ),
  route('POST', '/remote-login/:id/deny', async (request, env, params) =>
    handleRemoteLoginDeny(request, await remoteLoginDeps(request, env), params['id'] ?? ''),
  ),
  route('POST', '/remote-login/:id/exchange', async (request, env, params) =>
    handleRemoteLoginExchange(request, await remoteLoginDeps(request, env), params['id'] ?? ''),
  ),
  route('PATCH', '/ed25519/credentials/:id', async (request, env, params) =>
    handleEd25519CredentialUpdate(request, await ed25519Deps(request, env), params['id'] ?? ''),
  ),
  route('DELETE', '/ed25519/credentials/:id', async (request, env, params) =>
    handleEd25519CredentialDelete(request, await ed25519Deps(request, env), params['id'] ?? ''),
  ),
];

export function routeKeys(): string[] {
  return routes.map((entry) => `${entry.method} /${entry.segments.join('/')}`).sort();
}

function matchRoute(method: string, pathname: string): { route: Route; params: Params } | null {
  const parts = pathname.split('/').filter((segment) => segment.length > 0);
  for (const candidate of routes) {
    if (candidate.method !== method) continue;
    if (candidate.segments.length !== parts.length) continue;
    const params: Params = {};
    let matched = true;
    for (let index = 0; index < parts.length; index += 1) {
      const expected = candidate.segments[index]!;
      const actual = parts[index]!;
      if (expected.startsWith(':')) {
        params[expected.slice(1)] = decodeURIComponent(actual);
        continue;
      }
      if (expected !== actual) {
        matched = false;
        break;
      }
    }
    if (matched) return { route: candidate, params };
  }
  return null;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') return preflight();

    const { pathname } = new URL(request.url);
    const matched = matchRoute(request.method, pathname);
    if (!matched) return errorResponse(404, 'not_found');

    try {
      return await matched.route.handler(request, env, matched.params);
    } catch (error) {
      if (error instanceof ApiError) return errorResponse(error.status, error.code);
      // Malformed or over-strict bodies are a client error, never a leaked internal code.
      if (error instanceof StrictJsonError) return errorResponse(400, 'invalid_request');
      console.error('unhandled_error', error instanceof Error ? error.message : 'unknown');
      return errorResponse(500, 'internal_error');
    }
  },
};
