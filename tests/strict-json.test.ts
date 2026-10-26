import { describe, expect, it } from 'vitest';
import { StrictJsonError, optionalString, parseStrictJsonObject, rejectUnknownKeys, requireString } from '../src/http/strict-json';

describe('strict JSON decoding', () => {
  it('rejects duplicate keys, including nested ones', () => {
    expect(() => parseStrictJsonObject('{"a":1,"a":2}')).toThrow(StrictJsonError);
    expect(() => parseStrictJsonObject('{"outer":{"b":1,"b":2}}')).toThrow('duplicate_field');
  });

  it('allows the same key in sibling objects and across array items', () => {
    expect(() => parseStrictJsonObject('{"a":{"k":1},"b":{"k":2}}')).not.toThrow();
    expect(() => parseStrictJsonObject('{"items":[{"k":1},{"k":2}]}')).not.toThrow();
  });

  it('rejects non-object roots and malformed bodies', () => {
    expect(() => parseStrictJsonObject('[]')).toThrow('invalid_json_object');
    expect(() => parseStrictJsonObject('"text"')).toThrow('invalid_json_object');
    expect(() => parseStrictJsonObject('{')).toThrow();
    expect(() => parseStrictJsonObject('{"a":1} trailing')).toThrow();
  });

  it('does not confuse repeated string values with duplicate keys', () => {
    expect(() =>
      parseStrictJsonObject('{"username":"auth@ntnl.io","from_email":"auth@ntnl.io"}'),
    ).not.toThrow();
    expect(() => parseStrictJsonObject('{"a":["x","x",{"b":"x"}],"c":"x"}')).not.toThrow();
    expect(() => parseStrictJsonObject('{"a":1,"a":2}')).toThrow('duplicate_field');
  });

  it('mirrors serde deny_unknown_fields', () => {
    const body = parseStrictJsonObject('{"request_id":"x","extra":true}');
    expect(() => rejectUnknownKeys(body, ['request_id'])).toThrow('unknown_field');
    expect(() => rejectUnknownKeys(body, ['request_id', 'extra'])).not.toThrow();
  });

  it('reads required and optional strings without coercing', () => {
    const body = parseStrictJsonObject('{"email":"a@b.c","note":null}');
    expect(requireString(body, 'email')).toBe('a@b.c');
    expect(optionalString(body, 'note')).toBeNull();
    expect(() => requireString(body, 'note')).toThrow('invalid_field');
    expect(() => requireString(parseStrictJsonObject('{"email":""}'), 'email')).toThrow('invalid_field');
  });
});
