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
import type { AdminDeps } from './routes/admin';
import { handleAdminConfig, handleAdminSetup } from './routes/admin';
import type { SessionDeps } from './routes/session';
import { handleMe, handleSessionLogout, handleSessionRefresh, handleTime } from './routes/session';
import { handleJwks } from './routes/jwks';

type Handler = (request: Request, env: Env) => Promise<Response>;

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

async function adminDeps(request: Request, env: Env): Promise<AdminDeps> {
  return {
    ...(await sessionDeps(request, env)),
    adminStore: new D1AdminStore(env.DB),
    setupToken: env.ADMIN_SETUP_TOKEN ?? null,
  };
}

/**
 * Route table keyed by "METHOD /path". The legacy server dispatches on the same pair, so this
 * table stays the single place where contract coverage is visible.
 */
const routes = new Map<string, Handler>([
  ['GET /jwks', handleJwks],
  ['POST /email/start', async (request, env) => handleEmailStart(request, await emailDeps(request, env))],
  ['POST /email/verify', async (request, env) => handleEmailVerify(request, await emailDeps(request, env))],
  ['POST /session/refresh', async (request, env) => handleSessionRefresh(request, await sessionDeps(request, env))],
  ['POST /session/logout', async (request, env) => handleSessionLogout(request, await sessionDeps(request, env))],
  ['GET /me', async (request, env) => handleMe(request, await sessionDeps(request, env))],
  ['GET /time', async () => handleTime(new Date())],
  ['GET /admin/setup', async (request, env) => handleAdminSetup(request, await adminDeps(request, env))],
  ['PUT /admin/setup', async (request, env) => handleAdminSetup(request, await adminDeps(request, env))],
  ['GET /admin/config', async (request, env) => handleAdminConfig(request, await adminDeps(request, env))],
  ['PUT /admin/config', async (request, env) => handleAdminConfig(request, await adminDeps(request, env))],
]);

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
      // Malformed or over-strict bodies are a client error, never a leaked internal code.
      if (error instanceof StrictJsonError) return errorResponse(400, 'invalid_request');
      console.error('unhandled_error', error instanceof Error ? error.message : 'unknown');
      return errorResponse(500, 'internal_error');
    }
  },
};
