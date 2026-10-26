export interface SmtpConfig {
  id: number;
  host: string;
  port: number;
  username: string;
  password: string;
  fromEmail: string;
  fromName: string;
  secure: boolean;
  weight: number;
}

export interface SmtpConfigStore {
  listActive(): Promise<SmtpConfig[]>;
}

/**
 * Weighted pick over the active rows, matching `select_smtp_config`: rows ordered by id,
 * a draw in [0, totalWeight), then the first bucket whose cumulative weight covers it.
 */
export function pickWeighted(configs: readonly SmtpConfig[], draw: number): SmtpConfig | null {
  if (configs.length === 0) return null;
  const total = configs.reduce((sum, config) => sum + config.weight, 0);
  if (total <= 0) return null;
  const clamped = Math.min(Math.max(draw, 0), 0.999999999);
  let remaining = Math.floor(clamped * total);
  for (const config of configs) {
    remaining -= config.weight;
    if (remaining < 0) return config;
  }
  return configs[configs.length - 1] ?? null;
}
