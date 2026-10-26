const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const INDEX = new Map<string, number>([...ALPHABET].map((char, position) => [char, position]));

/** Bitcoin-alphabet base58 decode, used for Ed25519 public keys. */
export function base58Decode(value: string): Uint8Array {
  if (value.length === 0) throw new Error('invalid_base58');
  let zeros = 0;
  while (zeros < value.length && value[zeros] === '1') zeros += 1;

  const bytes: number[] = [];
  for (const char of value) {
    const digit = INDEX.get(char);
    if (digit === undefined) throw new Error('invalid_base58');
    let carry = digit;
    for (let index = 0; index < bytes.length; index += 1) {
      carry += bytes[index]! * 58;
      bytes[index] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const output = new Uint8Array(zeros + bytes.length);
  bytes.reverse().forEach((byte, index) => {
    output[zeros + index] = byte;
  });
  return output;
}

/** Bitcoin-alphabet base58 encode, the inverse of `base58Decode`. */
export function base58Encode(bytes: Uint8Array): string {
  const digits: number[] = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      carry += digits[index]! << 8;
      digits[index] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = '';
  for (const byte of bytes) {
    if (byte !== 0) break;
    output += '1';
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) output += ALPHABET[digits[index]!];
  return output;
}
