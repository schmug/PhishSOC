import { beforeEach, describe, expect, it, vi } from "vitest";
import { SmtpPermanentError } from "../../workers/lib/smtp-client";

// Mock only submitRaw; keep the real error classes.
vi.mock("../../workers/lib/smtp-client", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../../workers/lib/smtp-client")>();
	return { ...actual, submitRaw: vi.fn(async () => {}) };
});

import { submitRaw } from "../../workers/lib/smtp-client";
import { smtpRelayProvider } from "../../workers/providers/smtp-relay";
import type { Env } from "../../workers/types";

const policy = {
	target: { host: "smtp-relay.gmail.com", port: 587, implicitTls: false },
	credentialsSecret: "RELAY_CREDS_EXAMPLE_COM",
	actions: { allow: "relay", tag: "relay", quarantine: "hold", block: "drop" },
} as const;

const raw = new TextEncoder().encode("Subject: t\r\n\r\nbody\r\n");
const envelope = { mailFrom: "s@origin.test", rcptTo: "u@example.com" };

describe("SmtpRelayProvider.relayRaw", () => {
	beforeEach(() => vi.mocked(submitRaw).mockClear());

	it("resolves credentials from the named secret and calls submitRaw", async () => {
		const env = { RELAY_CREDS_EXAMPLE_COM: JSON.stringify({ user: "u", pass: "p" }) } as unknown as Env;
		await smtpRelayProvider.relayRaw(env, raw, envelope, policy);
		expect(submitRaw).toHaveBeenCalledWith(
			expect.objectContaining({
				host: "smtp-relay.gmail.com",
				port: 587,
				implicitTls: false,
				auth: { user: "u", pass: "p" },
				mailFrom: "s@origin.test",
				rcptTo: "u@example.com",
				raw,
			}),
		);
	});

	it("throws SmtpPermanentError when the secret is missing or malformed", async () => {
		await expect(
			smtpRelayProvider.relayRaw({} as Env, raw, envelope, policy),
		).rejects.toBeInstanceOf(SmtpPermanentError);
		const bad = { RELAY_CREDS_EXAMPLE_COM: "not-json" } as unknown as Env;
		await expect(
			smtpRelayProvider.relayRaw(bad, raw, envelope, policy),
		).rejects.toBeInstanceOf(SmtpPermanentError);
		expect(submitRaw).not.toHaveBeenCalled();
	});

	it("relays unauthenticated when the policy names no secret", async () => {
		const p = { ...policy, credentialsSecret: undefined };
		await smtpRelayProvider.relayRaw({} as Env, raw, envelope, p);
		expect(submitRaw).toHaveBeenCalledWith(expect.objectContaining({ auth: undefined }));
	});
});
