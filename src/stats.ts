import type { RequestStatsStore } from './stores';

/**
 * Request statistics.
 *
 * The legacy server counted requests in memory and reported "since start". A Worker has no
 * "since start": isolates come and go, and one user's requests land in whichever isolate is
 * warm. The counters therefore live in D1 with two consequences the contract has to state:
 * the window is fixed (24 h by default, not uptime), and a request costs one upsert.
 */
export const STATS_BUCKET_SECONDS = 300;
export const STATS_WINDOW_SECONDS = 24 * 60 * 60;
export const STATS_RETENTION_SECONDS = 30 * 24 * 60 * 60;
/** Probes are high-cardinality by nature (bots invent paths), so they age out sooner. */
export const PROBE_RETENTION_SECONDS = 7 * 24 * 60 * 60;
export const ENDPOINT_LIMIT = 100;
/** The legacy spec caps distinct unknown paths and aggregates the rest into one `(other)` row. */
export const PROBE_LIMIT = 50;
export const PROBE_PATH_LIMIT = 200;

export function bucketOf(epochSeconds: number): number {
  return Math.floor(epochSeconds / STATS_BUCKET_SECONDS) * STATS_BUCKET_SECONDS;
}

/** The spec's placeholder style (`/remote-login/{id}/approve`), not the route table's `:id`. */
export function endpointLabel(segments: readonly string[]): string {
  return `/${segments.map((segment) => (segment.startsWith(':') ? `{${segment.slice(1)}}` : segment)).join('/')}`;
}

export function truncateProbePath(path: string): string {
  return path.length <= PROBE_PATH_LIMIT ? path : `${path.slice(0, PROBE_PATH_LIMIT - 3)}...`;
}

export async function recordRequest(
  store: RequestStatsStore,
  input: { method: string; endpoint: string; status: number; ms: number; now: Date },
): Promise<void> {
  await store.recordHit({
    bucket: bucketOf(Math.floor(input.now.getTime() / 1000)),
    method: input.method,
    endpoint: input.endpoint,
    status: input.status,
    hits: 1,
    totalMs: Math.max(0, Math.round(input.ms)),
    now: Math.floor(input.now.getTime() / 1000),
  });
}

export async function recordProbe(
  store: RequestStatsStore,
  input: { method: string; path: string; now: Date },
): Promise<void> {
  await store.recordProbe({
    bucket: bucketOf(Math.floor(input.now.getTime() / 1000)),
    method: input.method,
    path: truncateProbePath(input.path),
    hits: 1,
    now: Math.floor(input.now.getTime() / 1000),
  });
}

export interface RequestAuditSnapshot {
  started_at: number;
  window_seconds: number;
  endpoints: Array<{ method: string; endpoint: string; count: number; error_count: number; mean_ms: number }>;
  unmatched: Array<{ method: string; path: string; count: number; last_seen: number }>;
}

/** Prunes expired buckets, then aggregates the window. */
export async function readRequestAudit(store: RequestStatsStore, now: Date): Promise<RequestAuditSnapshot> {
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const since = bucketOf(nowSeconds - STATS_WINDOW_SECONDS);
  await store.prune(bucketOf(nowSeconds - STATS_RETENTION_SECONDS));

  const summary = await store.summarize(since, { endpointLimit: ENDPOINT_LIMIT, probeLimit: PROBE_LIMIT });
  const unmatched = summary.probes.map((probe) => ({
    method: probe.method,
    path: probe.path,
    count: probe.count,
    last_seen: probe.lastSeen,
  }));
  if (summary.probeOverflow !== null) {
    unmatched.push({ method: '', path: '(other)', count: summary.probeOverflow.count, last_seen: summary.probeOverflow.lastSeen });
  }

  return {
    started_at: since,
    window_seconds: STATS_WINDOW_SECONDS,
    endpoints: summary.endpoints.map((entry) => ({
      method: entry.method,
      endpoint: entry.endpoint,
      count: entry.count,
      error_count: entry.errorCount,
      mean_ms: entry.count === 0 ? 0 : Math.round(entry.totalMs / entry.count),
    })),
    unmatched,
  };
}
