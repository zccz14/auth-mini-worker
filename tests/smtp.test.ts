import { describe, expect, it } from 'vitest';
import type { MailSocket } from '../src/mail/smtp';
import { SmtpError, dotStuff, sendSmtpMail, transportModeFor } from '../src/mail/smtp';

type Reply = string | string[] | null;

interface ServerOptions {
  /** Greeting sent on connect; null models a mid-stream upgrade, where no greeting follows. */
  greeting?: string | null;
}

/** A scripted SMTP server: records commands and answers through a callback. */
class FakeServer {
  readonly commands: string[] = [];
  readonly socket: MailSocket;
  private inData = false;
  private pending = '';
  private controller!: ReadableStreamDefaultController<Uint8Array>;

  constructor(
    private readonly reply: (command: string) => Reply,
    options: ServerOptions = {},
  ) {
    const greeting = options.greeting === undefined ? '220 fake ESMTP ready' : options.greeting;
    const readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.controller = controller;
        if (greeting !== null) this.write(`${greeting}\r\n`);
      },
    });
    const writable = new WritableStream<Uint8Array>({
      write: (chunk) => {
        this.pending += new TextDecoder().decode(chunk);
        for (;;) {
          const index = this.pending.indexOf('\r\n');
          if (index < 0) break;
          const line = this.pending.slice(0, index);
          this.pending = this.pending.slice(index + 2);
          if (this.inData) {
            if (line === '.') {
              this.inData = false;
              this.write('250 queued\r\n');
            }
            continue;
          }
          this.commands.push(line);
          if (line === 'DATA') this.inData = true;
          const answer = this.reply(line);
          if (answer === null) continue;
          const lines = Array.isArray(answer) ? answer : [answer];
          this.write(`${lines.join('\r\n')}\r\n`);
        }
      },
    });
    this.socket = { readable, writable, close: async () => undefined };
  }

  private write(text: string): void {
    this.controller.enqueue(new TextEncoder().encode(text));
  }
}

const endpoint = { host: 'smtp.example.com', port: 587, username: 'mailer', password: 'p@ss word', secure: true };
const envelope = { from: 'noreply@example.com', to: 'user@example.com', raw: 'Subject: hi\r\n\r\nbody\r\n.leading dot' };

function submissionServer(options: { auth?: string; starttls?: boolean } & ServerOptions = {}): FakeServer {
  return new FakeServer((command) => {
    if (command.startsWith('EHLO')) {
      const capabilities = [options.auth ?? 'AUTH PLAIN LOGIN'];
      if (options.starttls !== false) capabilities.push('STARTTLS');
      const lines = ['fake.local', ...capabilities];
      return lines.map((line, index) => (index === lines.length - 1 ? `250 ${line}` : `250-${line}`));
    }
    if (command === 'STARTTLS') return '220 ready';
    if (command.startsWith('AUTH PLAIN')) return '235 authenticated';
    if (command === 'AUTH LOGIN') return '334 VXNlcm5hbWU6';
    if (command.startsWith('MAIL FROM')) return '250 ok';
    if (command.startsWith('RCPT TO')) return '250 ok';
    if (command === 'DATA') return '354 go ahead';
    if (command === 'QUIT') return '221 bye';
    return '250 ok';
  }, options);
}

describe('SMTP submission', () => {
  it('upgrades with STARTTLS, authenticates and submits the message', async () => {
    const plain = submissionServer();
    const upgraded = submissionServer({ greeting: null });
    plain.socket.startTls = () => upgraded.socket;

    await sendSmtpMail(() => plain.socket, endpoint, envelope, { timeoutMs: 1000 });

    expect(plain.commands[0]).toBe('EHLO auth-mini-worker');
    expect(plain.commands).toContain('STARTTLS');
    expect(plain.commands.some((line) => line.startsWith('AUTH'))).toBe(false);

    const auth = upgraded.commands.find((line) => line.startsWith('AUTH PLAIN '))!;
    expect(atob(auth.slice('AUTH PLAIN '.length))).toBe('\u0000mailer\u0000p@ss word');
    expect(upgraded.commands).toContain('MAIL FROM:<noreply@example.com>');
    expect(upgraded.commands).toContain('RCPT TO:<user@example.com>');
    expect(upgraded.commands).toContain('DATA');
    expect(upgraded.commands).toContain('DATA');
    expect(upgraded.commands).toContain('QUIT');
  });

  it('refuses to hand credentials to a server without STARTTLS', async () => {
    const server = submissionServer({ starttls: false });
    const error = await sendSmtpMail(() => server.socket, endpoint, envelope, { timeoutMs: 1000 }).catch((caught: unknown) => caught);
    expect((error as SmtpError).stage).toBe('starttls');
    expect(server.commands.some((line) => line.startsWith('AUTH'))).toBe(false);
  });

  it('falls back to AUTH LOGIN when that is all the server offers', async () => {
    let stage = 0;
    const server = new FakeServer((command) => {
      if (command.startsWith('EHLO')) return ['250-fake.local', '250 AUTH LOGIN'];
      if (command === 'AUTH LOGIN') return '334 VXNlcm5hbWU6';
      if (stage === 0) {
        stage = 1;
        return '334 UGFzc3dvcmQ6';
      }
      if (stage === 1) {
        stage = 2;
        return '235 authenticated';
      }
      if (command.startsWith('MAIL FROM')) return '250 ok';
      if (command.startsWith('RCPT TO')) return '250 ok';
      if (command === 'DATA') return '354 go ahead';
      if (command === 'QUIT') return '221 bye';
      return '250 ok';
    });

    await sendSmtpMail(() => server.socket, { ...endpoint, port: 465 }, envelope, { timeoutMs: 1000 });

    expect(server.commands).toContain('AUTH LOGIN');
    expect(atob(server.commands[server.commands.indexOf('AUTH LOGIN') + 1]!)).toBe('mailer');
    expect(atob(server.commands[server.commands.indexOf('AUTH LOGIN') + 2]!)).toBe('p@ss word');
  });

  it('surfaces a rejected recipient instead of pretending to send', async () => {
    const server = new FakeServer((command) => {
      if (command.startsWith('EHLO')) return ['250-fake.local', '250 AUTH PLAIN'];
      if (command.startsWith('AUTH')) return '235 ok';
      if (command.startsWith('MAIL FROM')) return '250 ok';
      if (command.startsWith('RCPT TO')) return '550 no such user';
      return '250 ok';
    });

    const error = await sendSmtpMail(() => server.socket, { ...endpoint, port: 465 }, envelope, { timeoutMs: 1000 }).catch(
      (caught: unknown) => caught,
    );
    expect((error as SmtpError).stage).toBe('rcpt');
  });

  it('times out instead of hanging the request', async () => {
    const server = new FakeServer(() => null, { greeting: null });
    const error = await sendSmtpMail(() => server.socket, { ...endpoint, port: 465 }, envelope, { timeoutMs: 25 }).catch(
      (caught: unknown) => caught,
    );
    expect((error as SmtpError).stage).toBe('timeout');
  });
});

describe('transport mode', () => {
  it('follows the legacy secure+port rule', () => {
    expect(transportModeFor(true, 465)).toBe('implicit_tls');
    expect(transportModeFor(true, 587)).toBe('starttls');
    expect(transportModeFor(true, 25)).toBe('starttls');
    expect(transportModeFor(false, 587)).toBe('cleartext');
  });
});

describe('dotStuff', () => {
  it('protects leading dots and normalizes line endings', () => {
    expect(dotStuff('a\n.b\nc')).toBe('a\r\n..b\r\nc');
  });
});
