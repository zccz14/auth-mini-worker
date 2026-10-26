/**
 * The legacy server rejects unknown fields (`#[serde(deny_unknown_fields)]` on every
 * request struct) and fails on duplicate keys. JSON.parse is too permissive for both,
 * so request bodies go through this module instead of bare JSON.parse.
 */

export class StrictJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictJsonError';
  }
}

interface JsonFrame {
  kind: 'object' | 'array';
  keys: Set<string>;
  expectKey: boolean;
}

/**
 * Rejects duplicate keys inside one object, and nothing else.
 *
 * The previous version treated every string as a potential key, so a body that reused the same
 * string as two different values (`{"username":"a@b.c","from_email":"a@b.c"}`) was rejected as a
 * duplicate. Tracking object context is what makes it correct: only strings that sit in key
 * position count.
 */
function scanDuplicateKeys(text: string): void {
  let index = 0;
  const stack: JsonFrame[] = [];

  const readString = (): string => {
    index += 1;
    while (index < text.length) {
      const char = text[index];
      if (char === '\\') {
        index += 2;
        continue;
      }
      if (char === '"') {
        index += 1;
        return text.slice(0, index);
      }
      index += 1;
    }
    throw new StrictJsonError('unterminated_string');
  };

  while (index < text.length) {
    const char = text[index];
    const top = stack[stack.length - 1];

    if (char === '"') {
      const start = index;
      readString();
      const raw = text.slice(start, index);
      if (top?.kind === 'object' && top.expectKey) {
        if (top.keys.has(raw)) throw new StrictJsonError('duplicate_field');
        top.keys.add(raw);
        top.expectKey = false;
      }
      continue;
    }
    if (char === '{') {
      stack.push({ kind: 'object', keys: new Set(), expectKey: true });
      index += 1;
      continue;
    }
    if (char === '[') {
      stack.push({ kind: 'array', keys: new Set(), expectKey: false });
      index += 1;
      continue;
    }
    if (char === '}' || char === ']') {
      stack.pop();
      index += 1;
      continue;
    }
    if (char === ',') {
      if (top?.kind === 'object') top.expectKey = true;
      index += 1;
      continue;
    }
    if (char === ':') {
      if (top) top.expectKey = false;
      index += 1;
      continue;
    }
    index += 1;
  }
}

export function parseStrictJsonObject(raw: string): Record<string, unknown> {
  if (raw.length > 1_048_576) throw new StrictJsonError('body_too_large');
  scanDuplicateKeys(raw);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new StrictJsonError('invalid_json');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new StrictJsonError('invalid_json_object');
  }
  return parsed as Record<string, unknown>;
}

export function rejectUnknownKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new StrictJsonError('unknown_field');
  }
}

export function requireString(value: Record<string, unknown>, key: string): string {
  const found = value[key];
  if (typeof found !== 'string' || found.length === 0) throw new StrictJsonError('invalid_field');
  return found;
}

export function optionalString(value: Record<string, unknown>, key: string): string | null {
  const found = value[key];
  if (found === undefined || found === null) return null;
  if (typeof found !== 'string') throw new StrictJsonError('invalid_field');
  return found;
}

export function requireObject(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const found = value[key];
  if (typeof found !== 'object' || found === null || Array.isArray(found)) {
    throw new StrictJsonError('invalid_field');
  }
  return found as Record<string, unknown>;
}
