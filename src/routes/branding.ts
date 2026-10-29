import { jsonResponse } from '../http/response';
import type { AdminStore } from '../stores';

export interface BrandingDeps {
  adminStore: AdminStore;
}

/**
 * GET /branding — the public face of this instance.
 *
 * Branding is rendered to visitors who have not signed in: the login page, the tab title, the
 * console header. None of it is a secret — `issuer` and `rp_id` are already in every token and
 * every passkey ceremony — so it cannot live behind the admin token, and the first-run probe
 * cannot carry it either: that endpoint answers 403 once the root user is claimed, which is why
 * a renamed instance kept calling itself "auth-mini" on every logged-out page.
 */
export async function handleBranding(_request: Request, deps: BrandingDeps): Promise<Response> {
  const config = await deps.adminStore.readConfig();
  return jsonResponse({
    issuer: config.issuer,
    rp_id: config.rpId,
    brand_name: config.brandName,
    brand_background_image: config.brandBackgroundImage,
  });
}
