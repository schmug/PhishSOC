// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Minimal SMTP *submission* client for inline-gateway relay (issue #32).
 *
 * Workers cannot open port 25 (platform block), so this client only speaks
 * authenticated submission: 587 with STARTTLS or 465 with implicit TLS.
 * `cloudflare:sockets` is imported dynamically so Node-pool tests can load
 * this module and inject a fake `connectFn`.
 *
 * Error taxonomy is the caller's control flow (see relayAfterVerdict):
 * 4xx/timeout/drop → SmtpTransientError (throw to origin → MTA retry);
 * 5xx → SmtpPermanentError (alert, don't retry).
 */

export class SmtpTransientError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SmtpTransientError";
	}
}

export class SmtpPermanentError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SmtpPermanentError";
	}
}

export interface SmtpSocketLike {
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	startTls?: () => SmtpSocketLike;
	close: () => Promise<void>;
}

export type SmtpConnectFn = (
	addr: { hostname: string; port: number },
	options?: { secureTransport?: "on" | "off" | "starttls" },
) => SmtpSocketLike;

export interface SmtpSubmitOptions {
	host: string;
	port: number;
	implicitTls: boolean;
	auth?: { user: string; pass: string };
	mailFrom: string;
	rcptTo: string;
	raw: Uint8Array;
	heloHost?: string;
	timeoutMs?: number;
	connectFn?: SmtpConnectFn;
}

interface SmtpResponse {
	code: number;
	text: string;
}

/** Buffered CRLF line reader over a socket's readable stream. */
class LineReader {
	private buffer = "";
	private reader: ReadableStreamDefaultReader<Uint8Array>;
	private decoder = new TextDecoder();

	constructor(stream: ReadableStream<Uint8Array>, private timeoutMs: number) {
		this.reader = stream.getReader();
	}

	async readLine(): Promise<string> {
		while (true) {
			const idx = this.buffer.indexOf("\r\n");
			if (idx >= 0) {
				const line = this.buffer.slice(0, idx);
				this.buffer = this.buffer.slice(idx + 2);
				return line;
			}
			const next = await Promise.race([
				this.reader.read(),
				new Promise<never>((_, reject) =>
					setTimeout(() => reject(new SmtpTransientError("SMTP read timeout")), this.timeoutMs),
				),
			]);
			if (next.done) throw new SmtpTransientError("SMTP connection closed unexpectedly");
			this.buffer += this.decoder.decode(next.value, { stream: true });
		}
	}

	releaseLock(): void {
		this.reader.releaseLock();
	}
}

/** Read one (possibly multiline) SMTP response: lines until `NNN<SP>`. */
async function readResponse(lines: LineReader): Promise<SmtpResponse> {
	const collected: string[] = [];
	while (true) {
		const line = await lines.readLine();
		collected.push(line);
		if (/^\d{3} /.test(line)) {
			return { code: Number.parseInt(line.slice(0, 3), 10), text: collected.join("\n") };
		}
		if (!/^\d{3}-/.test(line)) {
			throw new SmtpTransientError(`Malformed SMTP response line: ${line}`);
		}
	}
}

function classify(res: SmtpResponse, context: string): never {
	const msg = `SMTP ${context} failed: ${res.text}`;
	if (res.code >= 500) throw new SmtpPermanentError(msg);
	throw new SmtpTransientError(msg);
}

/** Dot-stuff the payload and guarantee a trailing CRLF (RFC 5321 §4.5.2). */
export function dotStuff(raw: Uint8Array): Uint8Array {
	// Manual 1:1 decode — TextDecoder("latin1") is windows-1252 and corrupts
	// bytes 0x80–0x9F on round-trip (see latin1Decode in arc-seal.ts).
	let text = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < raw.length; i += CHUNK) {
		text += String.fromCharCode(...raw.subarray(i, i + CHUNK));
	}
	text = text.replace(/(^|\r\n)\./g, "$1..");
	if (!text.endsWith("\r\n")) text += "\r\n";
	const out = new Uint8Array(text.length);
	for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
	return out;
}

export async function submitRaw(opts: SmtpSubmitOptions): Promise<void> {
	const timeoutMs = opts.timeoutMs ?? 30_000;
	const heloHost = opts.heloHost ?? "phishsoc-gateway.invalid";
	const connectFn =
		opts.connectFn ??
		((await import("cloudflare:sockets")).connect as unknown as SmtpConnectFn);

	let socket: SmtpSocketLike;
	try {
		socket = connectFn(
			{ hostname: opts.host, port: opts.port },
			{ secureTransport: opts.implicitTls ? "on" : "starttls" },
		);
	} catch (e) {
		throw new SmtpTransientError(`SMTP connect failed: ${(e as Error).message}`);
	}

	let lines = new LineReader(socket.readable, timeoutMs);
	let writer = socket.writable.getWriter();
	const encoder = new TextEncoder();

	const send = async (cmd: string) => {
		await writer.write(encoder.encode(cmd + "\r\n"));
	};
	const expect = async (okCodes: number[], context: string): Promise<SmtpResponse> => {
		const res = await readResponse(lines);
		if (!okCodes.includes(res.code)) classify(res, context);
		return res;
	};

	try {
		await expect([220], "greeting");
		await send(`EHLO ${heloHost}`);
		await expect([250], "EHLO");

		if (!opts.implicitTls) {
			await send("STARTTLS");
			await expect([220], "STARTTLS");
			if (!socket.startTls) throw new SmtpTransientError("socket does not support startTls");
			lines.releaseLock();
			writer.releaseLock();
			socket = socket.startTls();
			lines = new LineReader(socket.readable, timeoutMs);
			writer = socket.writable.getWriter();
			await send(`EHLO ${heloHost}`);
			await expect([250], "EHLO (post-TLS)");
		}

		if (opts.auth) {
			await send(`AUTH PLAIN ${btoa(`\0${opts.auth.user}\0${opts.auth.pass}`)}`);
			await expect([235], "AUTH PLAIN");
		}

		await send(`MAIL FROM:<${opts.mailFrom}>`);
		await expect([250], "MAIL FROM");
		await send(`RCPT TO:<${opts.rcptTo}>`);
		await expect([250, 251], "RCPT TO");
		await send("DATA");
		await expect([354], "DATA");
		await writer.write(dotStuff(opts.raw));
		await writer.write(encoder.encode(".\r\n"));
		await expect([250], "message body");
		await send("QUIT");
	} finally {
		try {
			writer.releaseLock();
			await socket.close();
		} catch {
			/* connection teardown is best-effort */
		}
	}
}
