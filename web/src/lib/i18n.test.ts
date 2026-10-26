import { describe, expect, it } from 'vitest';
import { messages } from './i18n';

describe('messages', () => {
  it('has exactly two non-empty translations per key', () => {
    for (const [key, pair] of Object.entries(messages)) {
      expect(pair, key).toHaveLength(2);
      expect(pair[0].length, key).toBeGreaterThan(0);
      expect(pair[1].length, key).toBeGreaterThan(0);
    }
  });

  it('keeps keys flat', () => {
    for (const key of Object.keys(messages)) {
      expect(key.includes(' '), key).toBe(false);
      expect(key.split('.').length, key).toBeGreaterThan(1);
    }
  });

  it('keeps placeholders in both languages', () => {
    for (const [key, pair] of Object.entries(messages)) {
      const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
      expect(placeholders(pair[1]), key).toEqual(placeholders(pair[0]));
    }
  });
});
