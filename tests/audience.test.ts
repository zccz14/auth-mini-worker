import { describe, expect, it } from 'vitest';
import { AudienceError, resolveAudiences } from '../src/audience';

const issuer = 'https://auth.ntnl.io';

describe('audience resolution', () => {
  it('defaults to the issuer hostname when there is no redirect', () => {
    expect(resolveAudiences(issuer, {})).toEqual(['auth.ntnl.io']);
  });

  it('uses the redirect hostname and accepts an explicit matching audience', () => {
    expect(resolveAudiences(issuer, { redirectUri: 'https://linkit.ntnl.io/cb' })).toEqual(['linkit.ntnl.io']);
    expect(resolveAudiences(issuer, { redirectUri: 'https://linkit.ntnl.io/cb', audiences: ['linkit.ntnl.io', '1ex.ntnl.io'] })).toEqual([
      '1ex.ntnl.io',
      'linkit.ntnl.io',
    ]);
  });

  it('rejects explicit audiences without a redirect', () => {
    expect(() => resolveAudiences(issuer, { aud: 'linkit.ntnl.io' })).toThrow(AudienceError);
    expect(() => resolveAudiences(issuer, { redirectUri: 'https://linkit.ntnl.io', aud: 'a', audiences: ['b'] })).toThrow(AudienceError);
  });

  it('requires an explicit audience for loopback redirects and plain http elsewhere', () => {
    expect(() => resolveAudiences(issuer, { redirectUri: 'http://localhost:3000/cb' })).toThrow('audience_required');
    expect(resolveAudiences(issuer, { redirectUri: 'http://localhost:3000/cb', aud: 'localhost' })).toEqual(['localhost']);
    expect(() => resolveAudiences(issuer, { redirectUri: 'http://app.example.com/cb' })).toThrow('invalid_redirect_uri');
  });

  it('rejects duplicates and audiences that drop the callback host', () => {
    expect(() => resolveAudiences(issuer, { redirectUri: 'https://a.example.com', audiences: ['a.example.com', 'a.example.com'] })).toThrow('invalid_audience');
    expect(() => resolveAudiences(issuer, { redirectUri: 'https://a.example.com', audiences: ['b.example.com'] })).toThrow('audience_required');
  });
});
