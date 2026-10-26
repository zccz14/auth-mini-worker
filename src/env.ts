export interface Env {
  DB: D1Database;
  /** Static assets for the `/web/` GUI, built from `web/` by `pnpm web:build`. */
  ASSETS: Fetcher;
  /** Optional shared secret for the first-run /admin/setup window; set it in production. */
  ADMIN_SETUP_TOKEN?: string;
}
