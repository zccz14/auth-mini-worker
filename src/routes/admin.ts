import { base58Decode } from '../crypto/base58';
import { authenticateAccessToken } from '../auth';
import { jsonResponse, errorResponse } from '../http/response';
import { StrictJsonError, optionalString, parseStrictJsonObject, rejectUnknownKeys, requireObject, requireString } from '../http/strict-json';
import { adminJwksBody, rotateSigningKeys } from '../jwks';
import { normalizeAllowedOrigin, normalizeBrandName, normalizeRpId, validateRpIdForIssuer, AdminValidationError } from '../admin/validate';
import type { AdminStore, AppConfig, SmtpInput } from '../stores';
import type { SessionDeps } from './session';

export interface AdminDeps extends SessionDeps {
  adminStore: AdminStore;
  /** When set, /admin/setup also requires this token; production should always set it. */
  setupToken: string | null;
}

async function stateJson(adminStore: AdminStore): Promise<Record<string, unknown>> {
  const config = await adminStore.readConfig();
  const [adminEd25519, smtp] = await Promise.all([adminStore.firstAdminCredential(), adminStore.listSmtpSummaries()]);
  return {
    issuer: config.issuer,
    rp_id: config.rpId,
    brand_name: config.brandName,
    brand_background_image: config.brandBackgroundImage,
    admin_user_id: config.adminUserId,
    admin_ed25519: adminEd25519,
    // Wire shape is snake_case per AdminSmtpConfigSummary; the store speaks camelCase.
    smtp:
      smtp.length === 0
        ? null
        : smtp.map((row) => ({
            id: row.id,
            host: row.host,
            port: row.port,
            username: row.username,
            from_email: row.fromEmail,
            from_name: row.fromName,
            secure: row.secure,
            is_active: row.isActive,
            weight: row.weight,
          })),
  };
}

function setupGuard(request: Request, deps: AdminDeps): Response | null {
  if (deps.setupToken === null) return null;
  const presented = request.headers.get('x-admin-setup-token');
  if (presented !== deps.setupToken) return errorResponse(403, 'admin_setup_forbidden');
  return null;
}

/**
 * GET/PUT /admin/setup — first-run bootstrap.
 *
 * The legacy server gated this on loopback; a Worker has no loopback, so the gate is "no admin
 * exists yet" plus an optional shared token. Set ADMIN_SETUP_TOKEN in production: the window
 * between deploy and the owner claiming admin is otherwise open to anyone.
 */
export async function handleAdminSetup(request: Request, deps: AdminDeps): Promise<Response> {
  const denied = setupGuard(request, deps);
  if (denied) return denied;

  const config = await deps.adminStore.readConfig();
  if (request.method === 'GET') {
    if (config.adminUserId !== null) return errorResponse(403, 'admin_setup_forbidden');
    return jsonResponse(await stateJson(deps.adminStore));
  }

  if (config.adminUserId !== null) return errorResponse(409, 'already_initialized');

  let name: string;
  let publicKey: string;
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['admin_ed25519']);
    const credential = requireObject(body, 'admin_ed25519');
    rejectUnknownKeys(credential, ['name', 'public_key']);
    name = requireString(credential, 'name').trim();
    publicKey = requireString(credential, 'public_key').trim();
  } catch (error) {
    if (error instanceof StrictJsonError) return errorResponse(400, 'invalid_request');
    throw error;
  }
  if (name.length === 0) return errorResponse(400, 'invalid_request');

  let keyBytes: Uint8Array;
  try {
    keyBytes = base58Decode(publicKey);
  } catch {
    return errorResponse(400, 'invalid_request');
  }
  if (keyBytes.length !== 32) return errorResponse(400, 'invalid_request');

  try {
    await deps.adminStore.installAdminEd25519(name, publicKey, deps.now.toISOString());
  } catch (error) {
    if (error instanceof Error && error.message === 'public_key_taken') return errorResponse(400, 'invalid_request');
    throw error;
  }

  return jsonResponse(await stateJson(deps.adminStore));
}

function readSmtpInputs(value: unknown): SmtpInput[] | null {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value)) throw new StrictJsonError('invalid_field');
  return value.map((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) throw new StrictJsonError('invalid_field');
    const input = entry as Record<string, unknown>;
    rejectUnknownKeys(input, ['id', 'host', 'port', 'username', 'password', 'from_email', 'from_name', 'secure', 'weight']);
    const id = input['id'];
    if (id !== undefined && id !== null && typeof id !== 'number') throw new StrictJsonError('invalid_field');
    const port = input['port'];
    const weight = input['weight'];
    const secure = input['secure'];
    if (typeof port !== 'number' || typeof weight !== 'number' || typeof secure !== 'boolean') throw new StrictJsonError('invalid_field');
    return {
      id: typeof id === 'number' ? id : null,
      host: requireString(input, 'host').trim(),
      port,
      username: requireString(input, 'username').trim(),
      password: optionalString(input, 'password') ?? '',
      fromEmail: requireString(input, 'from_email').trim(),
      fromName: optionalString(input, 'from_name') ?? '',
      secure,
      weight,
      index,
    } satisfies SmtpInput & { index: number };
  });
}

async function requireAdmin(request: Request, deps: AdminDeps): Promise<Response | null> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');
  if (!(await deps.userStore.isAdmin(auth.userId))) return errorResponse(403, 'admin_required');
  return null;
}

/** GET /admin/jwks — CURRENT and STANDBY public material. */
export async function handleAdminJwks(request: Request, deps: AdminDeps): Promise<Response> {
  const denied = await requireAdmin(request, deps);
  if (denied) return denied;
  return jsonResponse(await adminJwksBody(deps.keyStore));
}

/** POST /admin/jwks/rotate — promote STANDBY, mint a fresh STANDBY. */
export async function handleAdminJwksRotate(request: Request, deps: AdminDeps): Promise<Response> {
  const denied = await requireAdmin(request, deps);
  if (denied) return denied;
  return jsonResponse(await rotateSigningKeys(deps.keyStore));
}

/** GET/PUT /admin/config — issuer, RP id, branding and the SMTP rows. */
export async function handleAdminConfig(request: Request, deps: AdminDeps): Promise<Response> {
  const auth = await authenticateAccessToken(request, deps);
  if (!auth) return errorResponse(401, 'invalid_access_token');
  if (!(await deps.userStore.isAdmin(auth.userId))) return errorResponse(403, 'admin_required');

  if (request.method === 'GET') return jsonResponse(await stateJson(deps.adminStore));

  let issuer: string;
  let rpId: string;
  let brandName: string;
  let brandBackgroundImage: string;
  let smtp: SmtpInput[] | null;

  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['issuer', 'rp_id', 'brand_name', 'brand_background_image', 'smtp']);
    issuer = normalizeAllowedOrigin(requireString(body, 'issuer'));
    rpId = normalizeRpId(requireString(body, 'rp_id'));
    brandName = normalizeBrandName(requireString(body, 'brand_name'));
    brandBackgroundImage = (optionalString(body, 'brand_background_image') ?? '').trim();
    validateRpIdForIssuer(issuer, rpId);
    smtp = readSmtpInputs(body['smtp']);
    if (smtp) {
      for (const input of smtp) {
        if (input.host.length === 0 || input.port <= 0 || input.username.length === 0 || input.fromEmail.length === 0 || input.weight <= 0) {
          return errorResponse(400, 'invalid_request');
        }
        if (input.id === null && input.password.length === 0) return errorResponse(400, 'invalid_request');
      }
    }
  } catch (error) {
    if (error instanceof StrictJsonError || error instanceof AdminValidationError) return errorResponse(400, 'invalid_request');
    throw error;
  }

  const config: Omit<AppConfig, 'adminUserId'> = { issuer, rpId, brandName, brandBackgroundImage };
  await deps.adminStore.writeConfig(config);
  if (smtp) {
    try {
      await deps.adminStore.replaceSmtp(smtp);
    } catch {
      return errorResponse(400, 'invalid_request');
    }
  }

  return jsonResponse(await stateJson(deps.adminStore));
}
