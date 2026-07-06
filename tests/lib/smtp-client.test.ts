import { describe, expect, it } from "vitest";
import {
	SmtpPermanentError,
	SmtpTransientError,
	submitRaw,
	type SmtpConnectFn,
	type SmtpSocketLike,
} from "../../workers/lib/smtp-client";

/**
 * Scripted fake SMTP server. Each entry: a regex the next client line must
 * match, and the reply to send. The greeting fires unprompted (expect: null).
 * `startTls()` continues the same script on a "new" socket.
 */
interface ScriptStep {
	expect: RegExp | null;
	reply: string;
}

function fakeSmtp(script: ScriptStep[]) {
	const clientLines: string[] = [];
	let step = 0;
	let controller!: ReadableStreamDefaultController<Uint8Array>;
	const enc = new TextEncoder();
	const dec = new TextDecoder();

	const pushReplies = () => {
		while (step < script.length && script[step].expect === null) {
			controller.enqueue(enc.encode(script[step].reply + "\r\n"));
			step++;
		}
	};

	const mkSocket = (): SmtpSocketLike => ({
		readable: new ReadableStream<Uint8Array>({
			start(c) {
				controller = c;
				pushReplies();
			},
		}),
		writable: new WritableStream<Uint8Array>({
			write(chunk) {
				// Accumulate and split on CRLF; DATA payload arrives as lines too.
				const text = dec.decode(chunk);
				for (const line of text.split("\r\n")) {
					if (line === "" && !text.endsWith("\r\n")) continue;
					if (line === "") continue;
					clientLines.push(line);
					const s = script[step];
					if (s?.expect && s.expect.test(line)) {
						controller.enqueue(enc.encode(s.reply + "\r\n"));
						step++;
						pushReplies();
					}
				}
			},
		}),
		startTls: () => mkSocket(),
		close: async () => {
			try {
				controller.close();
			} catch {
				/* already closed */
			}
		},
	});

	const connectFn: SmtpConnectFn = (addr) => {
		// Parse-compare, never substring (CodeQL js/incomplete-url-substring-sanitization).
		expect(addr.hostname).toBe("smtp-relay.gmail.com");
		return mkSocket();
	};
	return { connectFn, clientLines };
}

const RAW = new TextEncoder().encode(
	"Subject: t\r\n\r\nline one\r\n.hidden dot line\r\n",
);

const BASE = {
	host: "smtp-relay.gmail.com",
	port: 587,
	implicitTls: false,
	mailFrom: "sender@origin.test",
	rcptTo: "user@example.com",
	raw: RAW,
	timeoutMs: 2000,
};

function happyScript(): ScriptStep[] {
	return [
		{ expect: null, reply: "220 fake ESMTP" },
		{ expect: /^EHLO /, reply: "250-fake\r\n250-STARTTLS\r\n250 AUTH PLAIN" },
		{ expect: /^STARTTLS$/, reply: "220 go ahead" },
		{ expect: /^EHLO /, reply: "250-fake\r\n250 AUTH PLAIN" },
		{ expect: /^AUTH PLAIN /, reply: "235 ok" },
		{ expect: /^MAIL FROM:<sender@origin\.test>$/, reply: "250 ok" },
		{ expect: /^RCPT TO:<user@example\.com>$/, reply: "250 ok" },
		{ expect: /^DATA$/, reply: "354 go" },
		{ expect: /^\.$/, reply: "250 queued" },
		{ expect: /^QUIT$/, reply: "221 bye" },
	];
}

describe("submitRaw", () => {
	it("walks the full STARTTLS + AUTH submission flow and dot-stuffs", async () => {
		const { connectFn, clientLines } = fakeSmtp(happyScript());
		await submitRaw({ ...BASE, auth: { user: "u", pass: "p" }, connectFn });
		// AUTH PLAIN payload is base64("\0u\0p")
		expect(clientLines).toContain(`AUTH PLAIN ${btoa("\0u\0p")}`);
		// The leading-dot body line was stuffed on the wire.
		expect(clientLines).toContain("..hidden dot line");
		expect(clientLines).not.toContain(".hidden dot line");
	});

	it("throws SmtpTransientError on 4xx", async () => {
		const script = happyScript().slice(0, 5);
		script.push({ expect: /^MAIL FROM:/, reply: "451 try later" });
		const { connectFn } = fakeSmtp(script);
		await expect(
			submitRaw({ ...BASE, auth: { user: "u", pass: "p" }, connectFn }),
		).rejects.toBeInstanceOf(SmtpTransientError);
	});

	it("throws SmtpPermanentError on 5xx (bad credentials)", async () => {
		const script = happyScript().slice(0, 4);
		script.push({ expect: /^AUTH PLAIN /, reply: "535 auth failed" });
		const { connectFn } = fakeSmtp(script);
		await expect(
			submitRaw({ ...BASE, auth: { user: "u", pass: "p" }, connectFn }),
		).rejects.toBeInstanceOf(SmtpPermanentError);
	});

	it("skips STARTTLS on implicit TLS and skips AUTH without credentials", async () => {
		const script: ScriptStep[] = [
			{ expect: null, reply: "220 fake ESMTP" },
			{ expect: /^EHLO /, reply: "250 fake" },
			{ expect: /^MAIL FROM:<>$/, reply: "250 ok" },
			{ expect: /^RCPT TO:<user@example\.com>$/, reply: "250 ok" },
			{ expect: /^DATA$/, reply: "354 go" },
			{ expect: /^\.$/, reply: "250 queued" },
			{ expect: /^QUIT$/, reply: "221 bye" },
		];
		const { connectFn } = fakeSmtp(script);
		await submitRaw({ ...BASE, implicitTls: true, port: 465, mailFrom: "", connectFn });
	});
});
