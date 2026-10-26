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

function scanDuplicateKeys(text: string): void {
  let index = 0;
  const stack: Array<Set<string>> = [];

  const skipString = (): void => {
    index += 1;
    while (index < text.length) {
      const ch = text[index];
      if (ch === '\\') {
        index += 2;
        continue;
      }
      if (ch === '"') {
        index += 1;
        return;
      }
      index += 1;
    }
    throw new StrictJsonError('unterminated_string');
  };

  const readString = (): string => {
    const start = index;
    skipString();
    return text.slice(start, index);
  };

  while (index < text.length) {
    const ch = text[index];
    if (ch === '"') {
      const raw = readString();
      const current = stack[stack.length - 1];
      if (current) {
        if (current.has(raw)) throw new StrictJsonError('duplicate_field');
        current.add(raw);
      }
      continue;
    }
    if (ch === '{') {
      stack.push(new Set());
      index += 1;
      continue;
    }
    if (ch === '}') {
      stack.pop();
      index += 1;
      continue;
    }
    if (ch === '[') {
      stack.push(new Set());
      index += 1;
      continue;
    }
    if (ch === ']') {
      stack.pop();
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
