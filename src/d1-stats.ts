import type { EndpointTotals, ProbeTotals, RequestHit, RequestProbe, RequestStatsStore } from './stores';

interface EndpointRow {
  method: string;
  endpoint: string;
  count: number;
  error_count: number;
  total_ms: number;
}

interface ProbeRow {
  method: string;
  path: string;
  count: number;
  last_seen: number;
}

/**
 * The counters live in D1 because nothing else is shared between isolates. Writes are upserts on a
 * (bucket, method, endpoint, status) key, so a burst of traffic costs one row per status per
 * bucket instead of one row per request; reads are a single grouped scan of the retention window.
 */
export class D1RequestStatsStore implements RequestStatsStore {
  constructor(private readonly db: D1Database) {}

  async recordHit(hit: RequestHit): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO request_stats (bucket, method, endpoint, status, hits, total_ms, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(bucket, method, endpoint, status) DO UPDATE SET
           hits = request_stats.hits + excluded.hits,
           total_ms = request_stats.total_ms + excluded.total_ms,
           last_seen = excluded.last_seen`,
      )
      .bind(hit.bucket, hit.method, hit.endpoint, hit.status, hit.hits, hit.totalMs, hit.now)
      .run();
  }

  async recordProbe(probe: RequestProbe): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO request_probes (bucket, method, path, hits, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(bucket, method, path) DO UPDATE SET
           hits = request_probes.hits + excluded.hits,
           last_seen = excluded.last_seen`,
      )
      .bind(probe.bucket, probe.method, probe.path, probe.hits, probe.now)
      .run();
  }

  async summarize(
    sinceBucket: number,
    options: { endpointLimit: number; probeLimit: number },
  ): Promise<{
    endpoints: EndpointTotals[];
    probes: ProbeTotals[];
    probeOverflow: { count: number; lastSeen: number } | null;
  }> {
    const endpoints = await this.db
      .prepare(
        `SELECT method, endpoint, SUM(hits) AS count,
                SUM(CASE WHEN status >= 400 THEN hits ELSE 0 END) AS error_count,
                SUM(total_ms) AS total_ms
         FROM request_stats
         WHERE bucket >= ?1
         GROUP BY method, endpoint
         ORDER BY count DESC, endpoint ASC
         LIMIT ?2`,
      )
      .bind(sinceBucket, options.endpointLimit)
      .all<EndpointRow>();

    const probes = await this.db
      .prepare(
        `SELECT method, path, SUM(hits) AS count, MAX(last_seen) AS last_seen
         FROM request_probes
         WHERE bucket >= ?1
         GROUP BY method, path
         ORDER BY count DESC, path ASC
         LIMIT ?2`,
      )
      .bind(sinceBucket, options.probeLimit)
      .all<ProbeRow>();

    const total = await this.db
      .prepare('SELECT SUM(hits) AS count, MAX(last_seen) AS last_seen FROM request_probes WHERE bucket >= ?1')
      .bind(sinceBucket)
      .first<{ count: number | null; last_seen: number | null }>();

    const listed = probes.results.reduce((sum, row) => sum + row.count, 0);
    const overflowCount = (total?.count ?? 0) - listed;

    return {
      endpoints: endpoints.results.map((row) => ({
        method: row.method,
        endpoint: row.endpoint,
        count: row.count,
        errorCount: row.error_count,
        totalMs: row.total_ms,
      })),
      probes: probes.results.map((row) => ({
        method: row.method,
        path: row.path,
        count: row.count,
        lastSeen: row.last_seen,
      })),
      probeOverflow:
        overflowCount > 0
          ? { count: overflowCount, lastSeen: total?.last_seen ?? 0 }
          : null,
    };
  }

  async prune(beforeBucket: number): Promise<void> {
    await this.db.prepare('DELETE FROM request_stats WHERE bucket < ?1').bind(beforeBucket).run();
    await this.db.prepare('DELETE FROM request_probes WHERE bucket < ?1').bind(beforeBucket).run();
  }
}
