export interface Env {
  DB: D1Database;
  /** Optional shared secret for the first-run /admin/setup window; set it in production. */
  ADMIN_SETUP_TOKEN?: string;
}
