/**
 * Minimal SMTP submission client for Workers.
 *
 * Cloudflare blocks outbound port 25, so this is submission-only. Two shapes exist:
 *  - port 587 with STARTTLS: connect plain, EHLO, STARTTLS, upgrade, EHLO again, AUTH.
 *  - port 465 with implicit TLS: the socket is already encrypted when we start.
 * The socket is injectable, so the protocol below is tested without touching the network.
 */

export interface MailSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  /** Present only when the connection can be upgraded mid-stream (STARTTLS). */
  startTls?: () => MailSocket;
  close(): Promise<void>;
}

export interface SocketOptions {
  hostname: string;
  port: number;
  /** True when the factory must hand back an already-encrypted socket (implicit TLS). */
  implicitTls: boolean;
}

export type SocketFactory = (options: SocketOptions) => MailSocket | Promise<MailSocket>;

export interface SmtpEndpoint {
  host: string;
  port: number;
  username: string;
  password: string;
  secure: boolean;
}

export interface Envelope {
  from: string;
  to: string;
  raw: string;
}

export class SmtpError extends Error {
  constructor(readonly stage: string, readonly detail: string) {
    super(`${stage}: ${detail}`);
    this.name = 'SmtpError';
  }
}

const CRLF = '\r\n';

class LineReader {
  private buffer = '';
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader();
  }

  async readLine(): Promise<string> {
    for (;;) {
      const index = this.buffer.indexOf(CRLF);
      if (index >= 0) {
        const line = this.buffer.slice(0, index);
        this.buffer = this.buffer.slice(index + 2);
        return line;
      }
      const { value, done } = await this.reader.read();
      if (done) {
        if (this.buffer.length === 0) throw new SmtpError('read', 'connection closed');
        const line = this.buffer;
        this.buffer = '';
        return line;
      }
      this.buffer += new TextDecoder().decode(value, { stream: true });
    }
  }
}

function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Prefix a dot to any line that already starts with one, per RFC 5321 §4.5.2. */
export function dotStuff(raw: string): string {
  return raw
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((line) => (line.startsWith('.') ? `.${line}` : line))
    .join(CRLF);
}

export interface SendOptions {
  timeoutMs?: number;
  heloName?: string;
}

export async function sendSmtpMail(
  factory: SocketFactory,
  endpoint: SmtpEndpoint,
  envelope: Envelope,
  options: SendOptions = {},
): Promise<void> {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const heloName = options.heloName ?? 'auth-mini-worker';

  let socket = await factory({ hostname: endpoint.host, port: endpoint.port, implicitTls: endpoint.secure });
  let lines = new LineReader(socket.readable);
  let writer = socket.writable.getWriter();

  const send = async (text: string): Promise<void> => {
    await writer.write(new TextEncoder().encode(text));
  };

  const expect = async (stage: string, ...codes: string[]): Promise<string[]> => {
    const collected: string[] = [];
    for (;;) {
      const line = await lines.readLine();
      if (line.length < 3) throw new SmtpError(stage, `malformed reply ${JSON.stringify(line)}`);
      collected.push(line);
      const code = line.slice(0, 3);
      if (!codes.includes(code)) throw new SmtpError(stage, `${code} ${line.slice(4)}`);
      if (line.length === 3 || line[3] !== '-') return collected;
    }
  };

  const ehlo = async (): Promise<string[]> => {
    await send(`EHLO ${heloName}${CRLF}`);
    return expect('ehlo', '250');
  };

  const authenticate = async (capabilities: string[], mayAuth: boolean): Promise<void> => {
    if (endpoint.username.length === 0) return;
    if (!mayAuth) throw new SmtpError('auth', 'server did not offer AUTH');
    const authLine = capabilities.map((line) => line.slice(4).trim().toUpperCase()).find((line) => line.startsWith('AUTH')) ?? '';
    if (authLine.includes('PLAIN') || authLine.length === 0) {
      await send(`AUTH PLAIN ${toBase64(`\0${endpoint.username}\0${endpoint.password}`)}${CRLF}`);
      await expect('auth', '235');
      return;
    }
    if (authLine.includes('LOGIN')) {
      await send(`AUTH LOGIN${CRLF}`);
      await expect('auth', '334');
      await send(`${toBase64(endpoint.username)}${CRLF}`);
      await expect('auth', '334');
      await send(`${toBase64(endpoint.password)}${CRLF}`);
      await expect('auth', '235');
      return;
    }
    throw new SmtpError('auth', `no supported mechanism in ${authLine}`);
  };

  const work = async (): Promise<void> => {
    await expect('greeting', '220');
    let capabilities = await ehlo();

    const advertisesStartTls = capabilities.some((line) => line.slice(4).trim().toUpperCase() === 'STARTTLS');
    if (!endpoint.secure && advertisesStartTls) {
      await send(`STARTTLS${CRLF}`);
      await expect('starttls', '220');
      if (!socket.startTls) throw new SmtpError('starttls', 'socket cannot be upgraded');
      // Re-read the upgraded stream: the old reader/writer refer to the plaintext socket.
      try {
        writer.releaseLock();
      } catch {
        // already released
      }
      socket = socket.startTls();
      lines = new LineReader(socket.readable);
      writer = socket.writable.getWriter();
      capabilities = await ehlo();
    } else if (!endpoint.secure) {
      throw new SmtpError('starttls', 'server does not offer STARTTLS; refusing to send credentials in the clear');
    }

    await authenticate(capabilities, capabilities.some((line) => line.slice(4).trim().toUpperCase().startsWith('AUTH')));

    await send(`MAIL FROM:<${envelope.from}>${CRLF}`);
    await expect('mail', '250');
    await send(`RCPT TO:<${envelope.to}>${CRLF}`);
    await expect('rcpt', '250', '251');
    await send(`DATA${CRLF}`);
    await expect('data', '354');
    await send(`${dotStuff(envelope.raw)}${CRLF}.${CRLF}`);
    await expect('body', '250');
    await send(`QUIT${CRLF}`);
    await expect('quit', '221');
  };

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      work(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new SmtpError('timeout', `no completion in ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    try {
      writer.releaseLock();
    } catch {
      // a failed write already released it
    }
    await socket.close().catch(() => undefined);
  }
}

/**
 * Runtime factory for the Workers socket API. Kept behind a dynamic import so tests and
 * type-checking never need the `cloudflare:sockets` module.
 */
export const workerSocketFactory: SocketFactory = async ({ hostname, port, implicitTls }) => {
  const sockets = (await import(/* @vite-ignore */ 'cloudflare:sockets')) as {
    connect: (address: { hostname: string; port: number }, options?: { secureTransport?: 'off' | 'starttls' | 'on' }) => MailSocket;
  };
  return sockets.connect(
    { hostname, port },
    { secureTransport: implicitTls ? 'on' : 'starttls' },
  );
};
