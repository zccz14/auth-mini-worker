-- Request statistics: what this instance actually serves, and what strangers ask it for.
--
-- The legacy server kept these counters in process memory, which a Worker cannot do: an isolate
-- is short-lived and one request may run in any of several. D1 is the only shared place, so the
-- counters live here, bucketed — one row per (bucket, method, endpoint, status) written by an
-- upsert, not one row per request. At 5-minute buckets a busy endpoint still costs a single row
-- per status per bucket.
--
-- `request_probes` is the same idea for requests that matched no route: it is the security signal
-- (bots asking for /wp-login.php), so it is kept separately and pruned sooner.

CREATE TABLE IF NOT EXISTS request_stats (
  bucket INTEGER NOT NULL,
  method TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  status INTEGER NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0,
  total_ms INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (bucket, method, endpoint, status)
);

CREATE TABLE IF NOT EXISTS request_probes (
  bucket INTEGER NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (bucket, method, path)
);
