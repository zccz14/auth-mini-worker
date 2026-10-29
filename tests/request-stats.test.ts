import { describe, expect, it } from 'vitest';
import { ensureSigningKeys } from '../src/jwks';
import type { AdminDeps } from '../src/routes/admin';
import { handleAdminRequestAudit } from '../src/routes/admin';
import { mintSession } from '../src/session';
import {
  PROBE_RETENTION_SECONDS,
  STATS_BUCKET_SECONDS,
  STATS_RETENTION_SECONDS,
  STATS_WINDOW_SECONDS,
  bucketOf,
  endpointLabel,
  readRequestAudit,
  recordProbe,
  recordRequest,
  truncateProbePath,
} from '../src/stats';
import {
  MemoryAdminStore,
  MemoryCredentialStore,
  MemoryKeyStore,
  MemoryMailTemplateStore,
  MemoryRequestStatsStore,
  MemorySessionStore,
  MemoryUserStore,
  MemoryWebauthnStore,
} from './doubles';

const NOW = new Date('2026-10-27T12:00:00.000Z');
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);
const ISSUER = 'https://auth.ntnl.io';

describe('bucketing and labels', () => {
  it('floors to five-minute buckets', () => {
    expect(STATS_BUCKET_SECONDS).toBe(300);
    expect(bucketOf(NOW_SECONDS)).toBe(Math.floor(NOW_SECONDS / 300) * 300);
    expect(bucketOf(301)).toBe(300);
    expect(bucketOf(299)).toBe(0);
  });

  it('labels a route the way the contract spells placeholders', () => {
    expect(endpointLabel(['remote-login', ':id', 'approve'])).toBe('/remote-login/{id}/approve');
    expect(endpointLabel(['jwks'])).toBe('/jwks');
  });

  it('truncates long probe paths instead of storing them whole', () => {
    const long = `/${'a'.repeat(400)}`;
    const kept = truncateProbePath(long);
    expect(kept.length).toBe(200);
    expect(kept.endsWith('...')).toBe(true);
    expect(truncateProbePath('/wp-login.php')).toBe('/wp-login.php');
  });
});

describe('reading the window', () => {
  it('sums buckets, counts errors and averages latency inside the window only', async () => {
    const store = new MemoryRequestStatsStore();
    const inside = bucketOf(NOW_SECONDS);
    const expired = bucketOf(NOW_SECONDS - STATS_WINDOW_SECONDS - STATS_BUCKET_SECONDS);

    store.hits.push(
      { bucket: inside, method: 'POST', endpoint: '/email/start', status: 200, hits: 2, totalMs: 40, now: NOW_SECONDS },
      { bucket: inside, method: 'POST', endpoint: '/email/start', status: 503, hits: 1, totalMs: 5, now: NOW_SECONDS },
      { bucket: expired, method: 'POST', endpoint: '/email/start', status: 200, hits: 99, totalMs: 990, now: NOW_SECONDS },
    );
    store.probes.push(
      { bucket: inside, method: 'GET', path: '/wp-login.php', hits: 4, now: NOW_SECONDS - 5 },
      { bucket: expired, method: 'GET', path: '/old-probe', hits: 7, now: NOW_SECONDS },
    );

    const snapshot = await readRequestAudit(store, NOW);

    expect(snapshot.started_at).toBe(bucketOf(NOW_SECONDS - STATS_WINDOW_SECONDS));
    expect(snapshot.window_seconds).toBe(STATS_WINDOW_SECONDS);
    expect(snapshot.endpoints).toEqual([
      { method: 'POST', endpoint: '/email/start', count: 3, error_count: 1, mean_ms: 15 },
    ]);
    expect(snapshot.unmatched).toEqual([
      { method: 'GET', path: '/wp-login.php', count: 4, last_seen: NOW_SECONDS - 5 },
    ]);
    // Pruning is part of the read: counters older than retention are dropped.
    expect(store.prunedBefore).toEqual([bucketOf(NOW_SECONDS - STATS_RETENTION_SECONDS)]);
    expect(PROBE_RETENTION_SECONDS).toBeLessThan(STATS_RETENTION_SECONDS);
  });

  it('aggregates probe overflow into a single (other) row', async () => {
    const store = new MemoryRequestStatsStore();
    const bucket = bucketOf(NOW_SECONDS);
    for (let index = 0; index < 60; index += 1) {
      store.probes.push({ bucket, method: 'GET', path: `/bot-${index}`, hits: 1, now: NOW_SECONDS });
    }

    const snapshot = await readRequestAudit(store, NOW);
    expect(snapshot.unmatched).toHaveLength(51);
    const other = snapshot.unmatched.at(-1)!;
    expect(other.path).toBe('(other)');
    expect(other.count).toBe(10);
  });

  it('records one hit per request with its latency and bucket', async () => {
    const store = new MemoryRequestStatsStore();
    await recordRequest(store, { method: 'GET', endpoint: '/jwks', status: 200, ms: 7.4, now: NOW });
    await recordProbe(store, { method: 'GET', path: '/nope', now: NOW });

    expect(store.hits[0]).toEqual({
      bucket: bucketOf(NOW_SECONDS),
      method: 'GET',
      endpoint: '/jwks',
      status: 200,
      hits: 1,
      totalMs: 7,
      now: NOW_SECONDS,
    });
    expect(store.probes[0]).toMatchObject({ method: 'GET', path: '/nope', hits: 1, bucket: bucketOf(NOW_SECONDS) });
  });
});

describe('GET /admin/request-audit', () => {
  async function harness(options: { admin: boolean }) {
    const keyStore = new MemoryKeyStore();
    await ensureSigningKeys(keyStore);
    const sessionStore = new MemorySessionStore();
    const userStore = new MemoryUserStore();
    const requestStatsStore = new MemoryRequestStatsStore();
    const userId = await userStore.ensureByEmail('admin@example.com', NOW.toISOString());
    if (options.admin) userStore.adminId = userId;

    const pair = await mintSession({
      keyStore,
      sessionStore,
      issuer: ISSUER,
      userId,
      authMethod: 'email_otp',
      sourceAuthMethod: null,
      audiences: ['auth.ntnl.io'],
      ip: null,
      userAgent: null,
      isAdmin: options.admin,
      now: NOW,
    });

    const deps: AdminDeps = {
      issuer: ISSUER,
      keyStore,
      sessionStore,
      userStore,
      credentialStore: new MemoryCredentialStore(),
      now: NOW,
      adminStore: new MemoryAdminStore(),
      webauthnStore: new MemoryWebauthnStore(),
      requestStatsStore,
      mailTemplates: new MemoryMailTemplateStore(),
      setupToken: null,
    };

    function request(token?: string): Request {
      return new Request('https://auth.ntnl.io/admin/request-audit', {
        headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
      });
    }

    return { deps, request, token: pair.accessToken, requestStatsStore };
  }

  it('requires an admin session', async () => {
    const anonymous = await harness({ admin: true });
    const missing = await handleAdminRequestAudit(anonymous.request(), anonymous.deps);
    expect(missing.status).toBe(401);

    const plain = await harness({ admin: false });
    const forbidden = await handleAdminRequestAudit(plain.request(plain.token), plain.deps);
    expect(forbidden.status).toBe(403);
  });

  it('answers with the window, the endpoints and the probes', async () => {
    const { deps, request, token, requestStatsStore } = await harness({ admin: true });
    requestStatsStore.hits.push(
      { bucket: bucketOf(NOW_SECONDS), method: 'POST', endpoint: '/email/start', status: 200, hits: 12, totalMs: 120, now: NOW_SECONDS },
      { bucket: bucketOf(NOW_SECONDS), method: 'GET', endpoint: '/jwks', status: 200, hits: 3, totalMs: 6, now: NOW_SECONDS },
    );
    requestStatsStore.probes.push({ bucket: bucketOf(NOW_SECONDS), method: 'GET', path: '/wp-login.php', hits: 42, now: NOW_SECONDS - 60 });

    const response = await handleAdminRequestAudit(request(token), deps);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      started_at: bucketOf(NOW_SECONDS - STATS_WINDOW_SECONDS),
      window_seconds: STATS_WINDOW_SECONDS,
      endpoints: [
        { method: 'POST', endpoint: '/email/start', count: 12, error_count: 0, mean_ms: 10 },
        { method: 'GET', endpoint: '/jwks', count: 3, error_count: 0, mean_ms: 2 },
      ],
      unmatched: [{ method: 'GET', path: '/wp-login.php', count: 42, last_seen: NOW_SECONDS - 60 }],
    });
  });
});
