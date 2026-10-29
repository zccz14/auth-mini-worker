import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import openapiSource from '../openapi.yaml?raw';
import { routeKeys } from '../src/index';

/**
 * The vendored openapi.yaml is the contract Auth Mini shipped. Every route we implement
 * must exist in it — the reverse direction (the spec paths we have not built yet) is the
 * remaining work, tracked in docs/COMPATIBILITY.md rather than asserted here.
 */
const spec = parse(openapiSource) as { paths: Record<string, Record<string, unknown>> };

function matches(template: string, path: string): boolean {
  const pattern = template
    .split('/')
    .map((segment) => (/^[{:]/.test(segment) ? '[^/]+' : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    .join('/');
  return new RegExp(`^${pattern}$`).test(path);
}

describe('openapi contract', () => {
  it('vendors the full legacy surface plus the deliberate additions', () => {
    // 36 paths are the legacy surface, byte for byte. The additions are recorded in
    // docs/COMPATIBILITY.md:
    //   POST /admin/setup/passkey/options — the first-run claim registers a passkey, so a
    //   challenge has to be issued before the credential exists.
    //   GET /branding — branding is rendered to visitors who have not signed in, and the
    //   first-run probe answers 403 once the root user is claimed.
    expect(Object.keys(spec.paths)).toHaveLength(38);
  });

  it('implements no route the contract does not define', () => {
    for (const route of routeKeys()) {
      const [method, path] = route.split(' ') as [string, string];
      const covered = Object.entries(spec.paths).some(
        ([template, operations]) => matches(template, path) && method.toLowerCase() in operations,
      );
      expect(covered, `${route} missing from openapi.yaml`).toBe(true);
    }
  });
});
