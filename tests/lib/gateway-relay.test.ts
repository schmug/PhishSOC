import { beforeEach, describe, expect, it, vi } from "vitest";
import { prependHeaders, relayAfterVerdict } from "../../workers/lib/gateway-relay";
import { SmtpPermanentError, SmtpTransientError } from "../../workers/lib/smtp-client";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import type { Env } from "../../workers/types";
import type { FinalVerdict } from "../../workers/security/verdict";

const dec = new TextDecoder();

function verdict(action: FinalVerdict["action"], score = 42): FinalVerdict {
	return {
		action,
		score,
		confidence: 0.9,
		explanation: "test",
		auth: { spf: "pass", dkim: "pass", dmarc: "pass", dkimObservations: [] },
		classification: { verdict: "ok", confidence: 0.9 } as FinalVerdict["classification"],
		signals: [],
	};
}

const policy = {
	target: { host: "smtp-relay.gmail.com", port: 587, implicitTls: false },
	actions: { allow: "relay", tag: "relay", quarantine: "hold", block: "drop" },
} as const;

/** Env whose BUCKET serves org settings; no ARC key unless added. */
function fakeEnv(orgSettings: Record<string, unknown>, extra: Record<string, unknown> = {}): Env {
	return {
		BUCKET: {
			get: async (key: string) =>
				key === "org/settings.json"
					? { etag: "e1", json: async () => orgSettings }
					: null,
		},
		...extra,
	} as unknown as Env;
}

const RAW = new TextEncoder().encode("Subject: t\r\nFrom: a@b.test\r\n\r\nbody\r\n");

describe("prependHeaders", () => {
	it("prepends CRLF-terminated lines, byte-preserving the rest", () => {
		const out = prependHeaders(RAW, ["X-PhishPilot-Verdict: allow"]);
		expect(dec.decode(out)).toBe("X-PhishPilot-Verdict: allow\r\n" + dec.decode(RAW));
	});
	it("is a no-op for an empty list", () => {
		expect(prependHeaders(RAW, [])).toBe(RAW);
	});
});

describe("relayAfterVerdict", () => {
	beforeEach(() => clearOrgSettingsCache());

	const base = (relayFn: (...a: never[]) => Promise<void>, env = fakeEnv({})) => ({
		env,
		ctx: undefined,
		raw: RAW,
		policy,
		envelopeFrom: "sender@origin.test",
		rcptTo: "user@example.com",
		relayFn: relayFn as never,
	});

	it("hold and drop short-circuit without touching the wire", async () => {
		const relayFn = vi.fn(async () => {});
		expect(await relayAfterVerdict({ ...base(relayFn), verdict: verdict("quarantine") })).toBe("held");
		expect(await relayAfterVerdict({ ...base(relayFn), verdict: verdict("block") })).toBe("dropped");
		expect(relayFn).not.toHaveBeenCalled();
	});

	it("relays with verdict headers; no seal when ARC is unconfigured", async () => {
		let sent: Uint8Array | undefined;
		const relayFn = vi.fn(async (_e: Env, raw: Uint8Array) => {
			sent = raw;
		});
		const out = await relayAfterVerdict({ ...base(relayFn as never), verdict: verdict("tag", 55) });
		expect(out).toBe("relayed");
		const text = dec.decode(sent!);
		expect(text.startsWith("X-PhishPilot-Verdict: tag\r\nX-PhishPilot-Score: 55\r\n")).toBe(true);
		expect(text).not.toContain("ARC-Seal");
	});

	it("seals when org gateway config + key are present", async () => {
		const kp = await crypto.subtle.generateKey(
			{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
			true,
			["sign", "verify"],
		);
		const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", kp.privateKey)).toString("base64");
		const pem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----`;
		const env = fakeEnv(
			{ gateway: { arcSealerDomain: "gw.example.com", arcSelector: "arc1" } },
			{ ARC_SEAL_PRIVATE_KEY: pem },
		);
		let sent: Uint8Array | undefined;
		const relayFn = async (_e: Env, raw: Uint8Array) => {
			sent = raw;
		};
		const out = await relayAfterVerdict({ ...base(relayFn as never, env), verdict: verdict("allow") });
		expect(out).toBe("relayed");
		expect(dec.decode(sent!).startsWith("ARC-Seal: i=1;")).toBe(true);
	});

	it("a broken ARC key alerts and relays unsealed, never blocks delivery", async () => {
		const env = fakeEnv(
			{ gateway: { arcSealerDomain: "gw.example.com", arcSelector: "arc1" } },
			{ ARC_SEAL_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----" },
		);
		let sent: Uint8Array | undefined;
		const relayFn = async (_e: Env, raw: Uint8Array) => {
			sent = raw;
		};
		const out = await relayAfterVerdict({ ...base(relayFn as never, env), verdict: verdict("allow") });
		expect(out).toBe("relayed");
		expect(dec.decode(sent!)).not.toContain("ARC-Seal");
	});

	it("null verdict relays as-is: no headers, no seal (fail-open)", async () => {
		let sent: Uint8Array | undefined;
		const relayFn = async (_e: Env, raw: Uint8Array) => {
			sent = raw;
		};
		const out = await relayAfterVerdict({ ...base(relayFn as never), verdict: null });
		expect(out).toBe("relayed");
		expect(sent).toBe(RAW);
	});

	it("permanent failure: alerts + failed_permanent on registered path, throws on passthrough", async () => {
		const relayFn = async () => {
			throw new SmtpPermanentError("535 nope");
		};
		expect(await relayAfterVerdict({ ...base(relayFn as never), verdict: verdict("allow") })).toBe(
			"failed_permanent",
		);
		await expect(
			relayAfterVerdict({ ...base(relayFn as never), verdict: verdict("allow"), passthrough: true }),
		).rejects.toBeInstanceOf(SmtpPermanentError);
	});

	it("transient failure always rethrows (origin retries)", async () => {
		const relayFn = async () => {
			throw new SmtpTransientError("451 later");
		};
		await expect(
			relayAfterVerdict({ ...base(relayFn as never), verdict: verdict("allow") }),
		).rejects.toBeInstanceOf(SmtpTransientError);
	});
});
