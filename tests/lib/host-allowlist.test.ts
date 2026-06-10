// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Host-allowlist coverage for GHSA-jfj6-w954-96vg (findings f29 hub / f27
 * feed) — confused-deputy credential exfiltration.
 *
 * The `HUB_SECRET_` / `FEED_SECRET_` prefix guards (#415/#418) constrain
 * WHICH secret a teammate-editable settings blob may name, but not WHERE
 * that secret is sent. Without a destination pin, any authenticated
 * teammate who can edit `intel.hub.url` (or a `feed.url`) can point the
 * worker at `https://attacker.example` and receive the raw credential in
 * an `Authorization` header.
 *
 * This file asserts the missing half:
 *   1. `hostAllowed` — the shared helper: https-only, exact hostname
 *      match against a CSV allowlist (case-insensitive), defensive parse.
 *   2. `loadHubConfig` / `loadHubCredentials` — a hub credential is only
 *      resolvable when the hub URL's host is on `HUB_ALLOWED_HOSTS`.
 *      Unset/empty allowlist means the hub secret can never be sent →
 *      treated as not-configured (deliberate, documented behavior change:
 *      operators must set HUB_ALLOWED_HOSTS to use a hub secret).
 */

import { beforeEach, describe, expect, it } from "vitest";
import { hostAllowed } from "../../workers/lib/host-allowlist";
import { loadHubConfig, loadHubCredentials } from "../../workers/lib/hub-config";
import { clearOrgSettingsCache } from "../../workers/lib/org-settings";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";

// ── hostAllowed helper ────────────────────────────────────────────────

describe("hostAllowed", () => {
	it("allows an https URL whose hostname is on the CSV allowlist", () => {
		expect(hostAllowed("https://hub.example.com/api", "hub.example.com", [])).toBe(true);
	});

	it("rejects a hostname not on the allowlist", () => {
		expect(hostAllowed("https://attacker.example/api", "hub.example.com", [])).toBe(false);
	});

	it("rejects every host when the allowlist is unset or empty", () => {
		expect(hostAllowed("https://hub.example.com", undefined, [])).toBe(false);
		expect(hostAllowed("https://hub.example.com", "", [])).toBe(false);
		expect(hostAllowed("https://hub.example.com", " , ", [])).toBe(false);
	});

	it("rejects non-https schemes even for an allowlisted host", () => {
		expect(hostAllowed("http://hub.example.com", "hub.example.com", [])).toBe(false);
		expect(hostAllowed("ftp://hub.example.com", "hub.example.com", [])).toBe(false);
	});

	it("matches case-insensitively on both sides", () => {
		expect(hostAllowed("https://HUB.Example.COM/x", "Hub.EXAMPLE.com", [])).toBe(true);
	});

	it("parses CSV entries with whitespace and ignores empties", () => {
		expect(hostAllowed("https://b.example", " a.example , b.example ,, ", [])).toBe(true);
		expect(hostAllowed("https://c.example", " a.example , b.example ", [])).toBe(false);
	});

	it("requires exact hostname match — no suffix/substring tricks", () => {
		expect(hostAllowed("https://evilhub.example.com", "hub.example.com", [])).toBe(false);
		expect(hostAllowed("https://hub.example.com.attacker.example", "hub.example.com", [])).toBe(false);
	});

	it("returns false on a malformed URL instead of throwing", () => {
		expect(hostAllowed("not a url", "hub.example.com", [])).toBe(false);
		expect(hostAllowed("", "hub.example.com", [])).toBe(false);
	});

	it("unions extraHosts with the CSV allowlist (case-insensitive)", () => {
		expect(hostAllowed("https://default.feed.example", undefined, ["default.feed.example"])).toBe(true);
		expect(hostAllowed("https://Default.Feed.Example", "", ["default.feed.example"])).toBe(true);
		// extraHosts don't bypass the https requirement.
		expect(hostAllowed("http://default.feed.example", undefined, ["default.feed.example"])).toBe(false);
	});
});

// ── loadHubConfig / loadHubCredentials destination pin ────────────────

const MAILBOX_ID = "user@example.com";
const MAILBOX_KEY = `mailboxes/${MAILBOX_ID}.json`;

interface FakeBucket {
	get(key: string): Promise<{ etag: string; json(): Promise<unknown> } | null>;
}

function makeBucket(byKey: Record<string, unknown>): FakeBucket {
	let etag = 0;
	return {
		async get(key: string) {
			if (!(key in byKey)) return null;
			etag += 1;
			const body = JSON.stringify(byKey[key]);
			return {
				etag: `etag-${etag}`,
				async json() {
					return JSON.parse(body);
				},
			};
		},
	};
}

function hubEnv(opts: {
	hubUrl: string;
	allowedHosts?: string;
	secrets?: Record<string, string>;
}) {
	const bucket = makeBucket({
		[MAILBOX_KEY]: {
			intel: {
				hub: {
					url: opts.hubUrl,
					org_uuid: "org-uuid-1",
					api_key_secret_name: "HUB_SECRET_KEY",
					auto_report: true,
				},
			},
		},
	});
	return {
		BUCKET: bucket as unknown as R2Bucket,
		HUB_ALLOWED_HOSTS: opts.allowedHosts,
		...(opts.secrets ?? {}),
	};
}

describe("loadHubConfig — HUB_ALLOWED_HOSTS destination pin (GHSA-jfj6-w954-96vg f29)", () => {
	beforeEach(() => {
		clearOrgSettingsCache();
		clearDomainSettingsCache();
	});

	it("returns the config when the hub URL host is on HUB_ALLOWED_HOSTS (https)", async () => {
		const env = hubEnv({
			hubUrl: "https://hub.example.com",
			allowedHosts: "hub.example.com",
		});
		const cfg = await loadHubConfig(env, MAILBOX_ID);
		expect(cfg).not.toBeNull();
		expect(cfg?.url).toBe("https://hub.example.com");
		expect(cfg?.api_key_secret_name).toBe("HUB_SECRET_KEY");
	});

	it("returns null when the hub URL host is NOT on HUB_ALLOWED_HOSTS", async () => {
		const env = hubEnv({
			hubUrl: "https://attacker.example/collect",
			allowedHosts: "hub.example.com",
		});
		expect(await loadHubConfig(env, MAILBOX_ID)).toBeNull();
	});

	it("returns null when HUB_ALLOWED_HOSTS is unset — hub secret cannot be sent anywhere", async () => {
		const env = hubEnv({ hubUrl: "https://hub.example.com" });
		expect(await loadHubConfig(env, MAILBOX_ID)).toBeNull();
	});

	it("returns null when HUB_ALLOWED_HOSTS is empty", async () => {
		const env = hubEnv({ hubUrl: "https://hub.example.com", allowedHosts: "" });
		expect(await loadHubConfig(env, MAILBOX_ID)).toBeNull();
	});

	it("returns null for a non-https hub URL even when the host is allowlisted", async () => {
		const env = hubEnv({
			hubUrl: "http://hub.example.com",
			allowedHosts: "hub.example.com",
		});
		expect(await loadHubConfig(env, MAILBOX_ID)).toBeNull();
	});

	it("supports a multi-entry CSV allowlist", async () => {
		const env = hubEnv({
			hubUrl: "https://hub2.example.com",
			allowedHosts: "hub.example.com, hub2.example.com",
		});
		const cfg = await loadHubConfig(env, MAILBOX_ID);
		expect(cfg?.url).toBe("https://hub2.example.com");
	});
});

describe("loadHubCredentials — never resolves a secret for an off-allowlist hub", () => {
	beforeEach(() => {
		clearOrgSettingsCache();
		clearDomainSettingsCache();
	});

	it("returns the credentials for an allowlisted https hub", async () => {
		const env = hubEnv({
			hubUrl: "https://hub.example.com",
			allowedHosts: "hub.example.com",
			secrets: { HUB_SECRET_KEY: "live-api-key" },
		});
		const creds = await loadHubCredentials(env, MAILBOX_ID);
		expect(creds).not.toBeNull();
		expect(creds?.apiKey).toBe("live-api-key");
	});

	it("returns null (secret NOT exposed) when the hub URL host is off-allowlist", async () => {
		const env = hubEnv({
			hubUrl: "https://attacker.example",
			allowedHosts: "hub.example.com",
			secrets: { HUB_SECRET_KEY: "live-api-key" },
		});
		expect(await loadHubCredentials(env, MAILBOX_ID)).toBeNull();
	});

	it("returns null (secret NOT exposed) when HUB_ALLOWED_HOSTS is unset", async () => {
		const env = hubEnv({
			hubUrl: "https://hub.example.com",
			secrets: { HUB_SECRET_KEY: "live-api-key" },
		});
		expect(await loadHubCredentials(env, MAILBOX_ID)).toBeNull();
	});
});
