import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { authenticateAccessToken } from '../auth';
import { uuidv4 } from '../crypto/tokens';
import { jsonResponse, errorResponse } from '../http/response';
import { StrictJsonError, optionalString, parseStrictJsonObject, rejectUnknownKeys, requireString } from '../http/strict-json';
import { adminJwksBody, rotateSigningKeys } from '../jwks';
import {
  deriveSetupRelyingParty,
  normalizeAllowedOrigin,
  normalizeBrandName,
  normalizeRpId,
  validateRpIdForIssuer,
  AdminValidationError,
} from '../admin/validate';
import type { AdminStore, AppConfig, RequestStatsStore, SmtpInput, WebauthnStore } from '../stores';
import {
  MailTemplateError,
  parseMailTemplateOverrides,
  resolveMailTemplates,
  type MailTemplateOverrides,
  type MailTemplateStore,
} from '../mail/template';
import { readRequestAudit } from '../stats';
import { WEBAUTHN_CHALLENGE_SECONDS, newChallenge, registrationOptions, verifyRegistrationCeremony, webauthnUserHandleText } from '../webauthn';
import { REGISTER_INVALID, isUuid, parseRegistrationCredential, passkeyRecord, reportsNonDiscoverable } from './webauthn';
import type { SessionDeps } from './session';

export interface AdminDeps extends SessionDeps {
  adminStore: AdminStore;
  webauthnStore: WebauthnStore;
  requestStatsStore: RequestStatsStore;
  /** The two mail templates, stored beside the brand they are rendered with. */
  mailTemplates: MailTemplateStore;
  /** When set, /admin/setup also requires this token; production should always set it. */
  setupToken: string | null;
}

/**
 * The anonymous first-run projection: enough to decide whether the instance still needs its root
 * user and to render the unauthenticated shell. The administrator's credentials and the SMTP
 * fleet stay out of it — they belong to `/admin/config`, behind a token.
 */
async function bootstrapJson(adminStore: AdminStore): Promise<Record<string, unknown>> {
  const config = await adminStore.readConfig();
  return {
    issuer: config.issuer,
    rp_id: config.rpId,
    brand_name: config.brandName,
    brand_background_image: config.brandBackgroundImage,
    admin_user_id: config.adminUserId,
  };
}

/**
 * The full administrator view of `/admin/config`.
 *
 * Mail templates come back *resolved*: what the next message will actually say, defaults filled in.
 * An administrator therefore edits the wording rather than a diff against an invisible default,
 * and clearing a field stores `''` again — it is the default that comes back, not an empty mail.
 */
async function configJson(deps: AdminDeps): Promise<Record<string, unknown>> {
  const config = await deps.adminStore.readConfig();
  const [adminEd25519, smtp, mailTemplates] = await Promise.all([
    deps.adminStore.firstAdminCredential(),
    deps.adminStore.listSmtpSummaries(),
    deps.mailTemplates.read(),
  ]);
  const templates = resolveMailTemplates(mailTemplates.overrides);
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
    mail_templates: {
      login: { subject: templates.loginSubject, text: templates.loginText },
      email_change: { subject: templates.emailChangeSubject, text: templates.emailChangeText },
    },
  };
}

/**
 * `admin_setup_forbidden` means "already claimed", so a missing or wrong token needs its own code:
 * the GUI keys the whole first-run flow off that distinction.
 */
function setupGuard(request: Request, deps: AdminDeps): Response | null {
  if (deps.setupToken === null) return null;
  if (request.headers.get('x-admin-setup-token') !== deps.setupToken) {
    return errorResponse(403, 'admin_setup_token_required');
  }
  return null;
}

/**
 * GET /admin/setup — the first-run probe.
 *
 * The legacy server gated this on loopback; a Worker has no loopback, so the gate is "no root user
 * yet" plus an optional shared token. Once the owner claims the instance it answers 403
 * `admin_setup_forbidden`, which is the server reporting "already done" rather than a failure.
 */
export async function handleAdminSetup(request: Request, deps: AdminDeps): Promise<Response> {
  const denied = setupGuard(request, deps);
  if (denied) return denied;

  const config = await deps.adminStore.readConfig();
  if (config.adminUserId !== null) return errorResponse(403, 'admin_setup_forbidden');
  return jsonResponse(await bootstrapJson(deps.adminStore));
}

/**
 * POST /admin/setup/passkey/options — the first half of the one-time claim.
 *
 * A registration challenge carries a foreign key to `users`, so the root user row is created here,
 * before anything is verified. The claim itself waits for the credential: pointing
 * `admin_user_id` at a user with no passkey would leave an instance nobody can sign in to.
 *
 * The relying party comes from the request URL, because a fresh database still says `localhost`
 * and changing that needs the very token this endpoint exists to create.
 */
export async function handleAdminSetupPasskeyOptions(request: Request, deps: AdminDeps): Promise<Response> {
  const denied = setupGuard(request, deps);
  if (denied) return denied;

  const config = await deps.adminStore.readConfig();
  if (config.adminUserId !== null) return errorResponse(403, 'admin_setup_forbidden');

  try {
    rejectUnknownKeys(parseStrictJsonObject(await request.text()), []);
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  const relyingParty = deriveSetupRelyingParty(request.url);
  const rpName = config.brandName.trim();
  if (relyingParty === null || rpName.length === 0) return errorResponse(400, 'invalid_setup_origin');

  const userId = await deps.adminStore.ensureRootUser();
  const userHandle = await webauthnUserHandleText(userId);
  const challenge = newChallenge();
  const requestId = uuidv4();
  const now = deps.now.toISOString();
  const expiresAt = new Date(deps.now.getTime() + WEBAUTHN_CHALLENGE_SECONDS * 1000).toISOString();

  // One live claim challenge at a time, exactly like the authenticated registration route.
  await deps.webauthnStore.expirePendingRegistrations(userId, now);
  await deps.webauthnStore.insertChallenge({
    requestId,
    type: 'register',
    stateJson: JSON.stringify({ challenge, user_handle: userHandle }),
    userId,
    expiresAt,
    rpId: relyingParty.rpId,
    rpName,
    origin: relyingParty.issuer,
    now,
  });

  return jsonResponse({
    ...registrationOptions({ challenge, rpId: relyingParty.rpId, rpName, userHandle, userName: rpName }),
    request_id: requestId,
  });
}

/**
 * PUT /admin/setup — the second half: verify the passkey ceremony, store the credential, and only
 * then make that user the administrator. One-shot by construction: the `app_meta` update is
 * conditional on `admin_user_id IS NULL`, so a concurrent claim loses instead of sharing the role.
 */
export async function handleAdminSetupPasskey(request: Request, deps: AdminDeps): Promise<Response> {
  const denied = setupGuard(request, deps);
  if (denied) return denied;

  const config = await deps.adminStore.readConfig();
  if (config.adminUserId !== null) return errorResponse(409, 'already_initialized');

  let requestId: string;
  let credential: RegistrationResponseJSON;
  let declaredIssuer: string | null;
  let declaredRpId: string | null;
  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['request_id', 'credential', 'issuer', 'rp_id']);
    const parsedId = body['request_id'];
    if (typeof parsedId !== 'string' || !isUuid(parsedId)) throw new StrictJsonError('invalid_field');
    requestId = parsedId;
    const parsedCredential = parseRegistrationCredential(body['credential']);
    if (parsedCredential === null) throw new StrictJsonError('invalid_field');
    credential = parsedCredential;
    declaredIssuer = optionalString(body, 'issuer') ?? null;
    declaredRpId = optionalString(body, 'rp_id') ?? null;
  } catch {
    return errorResponse(400, 'invalid_request');
  }

  const relyingParty = deriveSetupRelyingParty(request.url);
  if (relyingParty === null) return errorResponse(400, 'invalid_setup_origin');
  // The page shows the inferred origin and sends it back. A mismatch means a stale tab or another
  // host, and silently claiming a relying party nobody confirmed would break every later ceremony.
  if (
    (declaredIssuer !== null && declaredIssuer !== relyingParty.issuer) ||
    (declaredRpId !== null && declaredRpId !== relyingParty.rpId)
  ) {
    return errorResponse(400, 'invalid_request');
  }

  const now = deps.now.toISOString();
  // A challenge issued for another origin must never complete here, or a claim could be replayed
  // against a host it was not created for.
  const challenge = await deps.webauthnStore.findChallenge(requestId, 'register');
  if (
    challenge === null ||
    challenge.userId === null ||
    challenge.consumedAt !== null ||
    challenge.expiresAt <= now ||
    challenge.origin !== relyingParty.issuer ||
    challenge.rpId !== relyingParty.rpId
  ) {
    return errorResponse(400, REGISTER_INVALID);
  }

  if (reportsNonDiscoverable(credential.clientExtensionResults)) return errorResponse(400, REGISTER_INVALID);

  let state: { challenge?: unknown; user_handle?: unknown };
  try {
    state = JSON.parse(challenge.stateJson) as { challenge?: unknown; user_handle?: unknown };
  } catch {
    return errorResponse(400, REGISTER_INVALID);
  }
  if (typeof state.challenge !== 'string' || typeof state.user_handle !== 'string') {
    return errorResponse(400, REGISTER_INVALID);
  }

  const outcome = await verifyRegistrationCeremony({
    response: credential,
    challenge: state.challenge,
    origin: challenge.origin,
    rpId: challenge.rpId,
  });
  if (outcome === null) return errorResponse(400, REGISTER_INVALID);

  const stored = await deps.webauthnStore.completeRegistration({
    requestId,
    credentialId: outcome.credentialId,
    userId: challenge.userId,
    passkeyJson: passkeyRecord(outcome, state.user_handle, challenge.rpId),
    rpId: challenge.rpId,
    firstOnly: true,
    now,
  });
  if (!stored.consumed) return errorResponse(400, REGISTER_INVALID);
  if (!stored.stored) return errorResponse(409, 'already_initialized');

  // Claim last: `admin_user_id` on a user without a credential is an instance with no way in.
  if (!(await deps.adminStore.claimRootUser(challenge.userId, relyingParty))) {
    return errorResponse(409, 'already_initialized');
  }

  return jsonResponse({ ok: true });
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

/**
 * GET /admin/request-audit — what this instance actually serves, and what strangers ask it for.
 *
 * The counters come from D1, not from a process: `started_at` is the start of a fixed window
 * (24 h), not the moment a server booted. Beyond the legacy columns the payload carries
 * `error_count` and `mean_ms` per endpoint and `window_seconds` — the numbers an outside reader
 * needs to tell "busy" from "broken".
 */
export async function handleAdminRequestAudit(request: Request, deps: AdminDeps): Promise<Response> {
  const denied = await requireAdmin(request, deps);
  if (denied) return denied;
  return jsonResponse(await readRequestAudit(deps.requestStatsStore, deps.now));
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

  if (request.method === 'GET') return jsonResponse(await configJson(deps));

  let issuer: string;
  let rpId: string;
  let brandName: string;
  let brandBackgroundImage: string;
  let smtp: SmtpInput[] | null;
  let mailTemplates: MailTemplateOverrides | null = null;

  try {
    const body = parseStrictJsonObject(await request.text());
    rejectUnknownKeys(body, ['issuer', 'rp_id', 'brand_name', 'brand_background_image', 'smtp', 'mail_templates']);
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
    const rawTemplates = body['mail_templates'];
    // Absent means "leave the templates alone", exactly like `smtp`; a typo inside them is a 400,
    // never a silently dropped template that mails the old wording.
    if (rawTemplates !== undefined && rawTemplates !== null) mailTemplates = parseMailTemplateOverrides(rawTemplates);
  } catch (error) {
    if (error instanceof StrictJsonError || error instanceof AdminValidationError || error instanceof MailTemplateError) {
      return errorResponse(400, 'invalid_request');
    }
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
  if (mailTemplates) await deps.mailTemplates.write(mailTemplates);

  return jsonResponse(await configJson(deps));
}
