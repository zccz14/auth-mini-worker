import { describe, expect, it } from 'vitest';
import { b64urlDecode, b64urlDecodeText, b64urlEncode, b64urlEncodeText } from '../src/crypto/b64url';

describe('b64url', () => {
  it('encodes without padding', () => {
    expect(b64urlEncodeText('hello')).toBe('aGVsbG8');
    expect(b64urlEncode(new Uint8Array([0]))).toBe('AA');
    expect(b64urlEncode(new Uint8Array([]))).toBe('');
  });

  it('round-trips arbitrary bytes', () => {
    for (const length of [0, 1, 2, 3, 31, 32, 64, 65]) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      expect(b64urlDecode(b64urlEncode(bytes))).toEqual(bytes);
    }
  });

  it('rejects padding and foreign characters', () => {
    expect(() => b64urlDecode('aGVsbG8=')).toThrow('invalid_base64url');
    expect(() => b64urlDecode('aGVsbG8+')).toThrow('invalid_base64url');
    expect(() => b64urlDecode('aGVsbG8/')).toThrow('invalid_base64url');
  });

  it('rejects impossible lengths and non-canonical trailing bits', () => {
    expect(() => b64urlDecode('A')).toThrow('invalid_base64url');
    expect(b64urlDecode('AA')).toEqual(new Uint8Array([0]));
    expect(() => b64urlDecode('AB')).toThrow('invalid_base64url');
  });

  it('round-trips UTF-8 text', () => {
    expect(b64urlDecodeText(b64urlEncodeText('认证 mini'))).toBe('认证 mini');
  });
});
