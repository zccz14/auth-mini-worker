import { describe, expect, it } from 'vitest';
import { authorizeBody, buildCallbackUrl, parseLoginRequest } from './login-request';
import type { TokenPair } from './api';

const TOKENS: TokenPair = {
  session_id: 'session-1',
  access_token: 'access-1',
  token_type: 'Bearer',
  expires_in: 900,
  refresh_token: 'refresh-1',
};

describe('parseLoginRequest', () => {
  it('treats a bare /login as the main site', () => {
    expect(parseLoginRequest('')).toEqual({ status: 'ready', state: null, target: { kind: 'self' } });
  });

  it('derives the audience from an https callback', () => {
    const request = parseLoginRequest('?redirect_uri=https%3A%2F%2Flinkit.ntnl.io%2Fcb&state=abc');
    expect(request).toEqual({
      status: 'ready',
      state: 'abc',
      target: { kind: 'redirect', audiences: null, redirectUri: 'https://linkit.ntnl.io/cb', displayHost: 'linkit.ntnl.io' },
    });
  });

  it('accepts an explicit audiences list that includes the callback host', () => {
    const request = parseLoginRequest(
      `?redirect_uri=${encodeURIComponent('https://linkit.ntnl.io/cb')}&audiences=${encodeURIComponent('["linkit.ntnl.io","ctx.ntnl.io"]')}`,
    );
    expect(request.status).toBe('ready');
    if (request.status !== 'ready') return;
    expect(authorizeBody(request.target)).toEqual({
      redirect_uri: 'https://linkit.ntnl.io/cb',
      audiences: ['linkit.ntnl.io', 'ctx.ntnl.io'],
    });
  });

  it('requires an explicit audience set for a loopback callback, including the callback host', () => {
    // `resolve_audiences` demands that the explicit set contains the callback hostname, so a
    // localhost callback must name localhost — that is what the server does, whatever the docs say.
    const request = parseLoginRequest(
      `?redirect_uri=${encodeURIComponent('http://localhost:5173/cb')}&audiences=${encodeURIComponent('["localhost","linkit.ntnl.io"]')}`,
    );
    expect(request.status).toBe('ready');
    if (request.status !== 'ready') return;
    expect(request.target.kind).toBe('loopback');
    expect(authorizeBody(request.target)).toEqual({
      redirect_uri: 'http://localhost:5173/cb',
      audiences: ['localhost', 'linkit.ntnl.io'],
    });

    const single = parseLoginRequest(`?redirect_uri=${encodeURIComponent('http://127.0.0.1:5173/cb')}&aud=127.0.0.1`);
    expect(single.status).toBe('ready');
    if (single.status !== 'ready') return;
    expect(authorizeBody(single.target)).toEqual({ redirect_uri: 'http://127.0.0.1:5173/cb', audiences: ['127.0.0.1'] });
  });

  it('rejects the combinations the server would reject', () => {
    expect(parseLoginRequest('?redirect_uri=not-a-url').status).toBe('invalid');
    expect(parseLoginRequest(`?redirect_uri=${encodeURIComponent('http://linkit.ntnl.io/cb')}`)).toEqual({
      status: 'invalid',
      reason: 'https_required',
    });
    expect(parseLoginRequest('?aud=linkit.ntnl.io')).toEqual({ status: 'invalid', reason: 'audience_rules' });
    expect(
      parseLoginRequest(`?redirect_uri=${encodeURIComponent('http://localhost:5173/cb')}&aud=evil.example`),
    ).toEqual({ status: 'invalid', reason: 'audience_rules' });
    expect(
      parseLoginRequest(
        `?redirect_uri=${encodeURIComponent('https://linkit.ntnl.io/cb')}&aud=linkit.ntnl.io`,
      ),
    ).toEqual({ status: 'invalid', reason: 'audience_rules' });
  });

  it('reads parameters that sit before the hash, for older entry points', () => {
    const request = parseLoginRequest('', '?redirect_uri=https%3A%2F%2Flinkit.ntnl.io%2Fcb');
    expect(request.status).toBe('ready');
  });
});

describe('buildCallbackUrl', () => {
  it('puts the token pair and the state in the fragment, keeping the path and query', () => {
    const url = buildCallbackUrl({
      redirectUri: 'https://linkit.ntnl.io/auth/callback?keep=1',
      state: 'state-123',
      tokens: TOKENS,
    });
    const parsed = new URL(url);
    expect(parsed.pathname).toBe('/auth/callback');
    expect(parsed.search).toBe('?keep=1');
    const fragment = new URLSearchParams(parsed.hash.slice(1));
    expect(fragment.get('access_token')).toBe('access-1');
    expect(fragment.get('refresh_token')).toBe('refresh-1');
    expect(fragment.get('session_id')).toBe('session-1');
    expect(fragment.get('expires_in')).toBe('900');
    expect(fragment.get('token_type')).toBe('Bearer');
    expect(fragment.get('state')).toBe('state-123');
  });

  it('keeps an existing fragment instead of overwriting it', () => {
    const url = buildCallbackUrl({ redirectUri: 'https://linkit.ntnl.io/cb#route=x', state: null, tokens: TOKENS });
    const fragment = new URLSearchParams(new URL(url).hash.slice(1));
    expect(fragment.get('route')).toBe('x');
    expect(fragment.get('access_token')).toBe('access-1');
    expect(fragment.get('state')).toBeNull();
  });
});
