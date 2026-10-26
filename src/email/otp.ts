/** OTP rules copied from auth-mini: 6 zero-padded digits, 10 minutes, sha256-hex at rest. */

export const OTP_SECONDS = 600;

export function generateOtpCode(): string {
  return (crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000).toString().padStart(6, '0');
}

/** Legacy `is_email_address`: a single `@` with both sides non-empty. */
export function isEmailAddress(value: string): boolean {
  const index = value.indexOf('@');
  if (index <= 0) return false;
  if (value.indexOf('@', index + 1) !== -1) return false;
  return index < value.length - 1;
}

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

export function isSixDigitCode(value: string): boolean {
  return /^[0-9]{6}$/.test(value);
}
