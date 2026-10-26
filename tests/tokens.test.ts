import { describe, expect, it } from 'vitest';
import { nowRfc3339Millis, randomHex, sha256Hex, uuidv4 } from '../src/crypto/tokens';

describe('token material', () => {
  it('produces the legacy 64-char lowercase hex refresh token', () => {
    const token = randomHex(32);
    expect(token).toHaveLength(64);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hashes the way sessions.refresh_token_hash was stored', async () => {
    expect(await sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(await sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('formats session ids as lowercase uuid v4', () => {
    expect(uuidv4()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('formats timestamps the way expires_at was stored', () => {
    expect(nowRfc3339Millis()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });
});
