// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tiered new-email webhook resolution — per-mailbox / per-domain / per-org.
 *
 * Settings tiers hold the NAME of a Worker Secret, never the URL itself: the
 * settings GET endpoints return these blobs to the client
 * (`workers/index.ts` `/api/v1/org/settings`, `/api/v1/domains/:domain/settings`),
 * so a raw webhook URL stored here would be a bearer credential readable by
 * every Access-authenticated user, and writable into a redirect of all mail
 * metadata. Same contract as `relay.credentialsSecret`
 * (`shared/domain-settings.ts:57`), including the enforced name prefix that
 * stops a settings write from naming an unrelated secret.
 *
 * Resolution is override semantics — most specific tier wins, whole-object
 * replace — matching how `security`, `intel`, and every other block resolves
 * in `resolveMailboxSettings`.
 */

import { describe, expect, it } from "vitest";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";
import {
	NEW_EMAIL_WEBHOOK_SECRET_PREFIX,
	resolveNewEmailWebhook,
} from "../../workers/lib/new-email-webhook-policy";
import { MailboxSettings } from "../../shared/mailbox-settings";
import { DomainSettings } from "../../shared/domain-settings";
import { OrgSettings } from "../../shared/org-settings";

const ORG_SECRET = "NEW_EMAIL_WEBHOOK_ORG_SOC";
const DOMAIN_SECRET = "NEW_EMAIL_WEBHOOK_ACME";
const MAILBOX_SECRET = "NEW_EMAIL_WEBHOOK_GROK";

describe("resolveNewEmailWebhook — tier precedence", () => {
	it("reports unconfigured when no tier sets a block, so the caller can fall back to the global secret", () => {
		expect(resolveNewEmailWebhook({})).toEqual({ configured: false, secretName: null, format: "chat" });
		expect(resolveNewEmailWebhook({ raw: {}, domain: {}, org: {} })).toEqual({
			configured: false,
			secretName: null,
			format: "chat",
		});
	});

	it("uses the org tier when it is the only one configured", () => {
		expect(
			resolveNewEmailWebhook({ org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET } } }),
		).toEqual({ configured: true, secretName: ORG_SECRET, format: "chat" });
	});

	it("prefers domain over org", () => {
		expect(
			resolveNewEmailWebhook({
				domain: { newEmailWebhook: { enabled: true, urlSecret: DOMAIN_SECRET } },
				org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET } },
			}),
		).toEqual({ configured: true, secretName: DOMAIN_SECRET, format: "chat" });
	});

	it("prefers mailbox over domain and org", () => {
		expect(
			resolveNewEmailWebhook({
				raw: { newEmailWebhook: { enabled: true, urlSecret: MAILBOX_SECRET } },
				domain: { newEmailWebhook: { enabled: true, urlSecret: DOMAIN_SECRET } },
				org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET } },
			}),
		).toEqual({ configured: true, secretName: MAILBOX_SECRET, format: "chat" });
	});
});

describe("resolveNewEmailWebhook — muting", () => {
	it("treats enabled:false on the winning tier as muted, not as a reason to inherit", () => {
		// A noisy mailbox opts out. It must NOT fall through to the org channel:
		// silently re-routing muted mail to a wider audience is the opposite of
		// what the operator asked for.
		expect(
			resolveNewEmailWebhook({
				raw: { newEmailWebhook: { enabled: false } },
				org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET } },
			}),
		).toEqual({ configured: true, secretName: null, format: "chat" });
	});

	it("treats a block with no urlSecret as configured-but-incomplete rather than inheriting", () => {
		expect(
			resolveNewEmailWebhook({
				domain: { newEmailWebhook: { enabled: true } },
				org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET } },
			}),
		).toEqual({ configured: true, secretName: null, format: "chat" });
	});

	it("stays configured (suppressing the global fallback) even when muted at the org tier", () => {
		expect(resolveNewEmailWebhook({ org: { newEmailWebhook: { enabled: false } } })).toEqual({
			configured: true,
			secretName: null,
			format: "chat",
		});
	});

	it("requires an explicit enabled:true, matching relay's fail-closed contract", () => {
		// `resolveRelayPolicy` treats an absent `enabled` as off. An outbound
		// data flow should default to off, so a half-written block does not
		// start shipping mail metadata off-platform.
		expect(
			resolveNewEmailWebhook({ org: { newEmailWebhook: { urlSecret: ORG_SECRET } } }),
		).toEqual({ configured: true, secretName: null, format: "chat" });
	});
});

describe("NewEmailWebhookSettings schema", () => {
	it("accepts a valid block on all three tiers", () => {
		const block = { newEmailWebhook: { enabled: true, urlSecret: MAILBOX_SECRET } };
		expect(MailboxSettings.safeParse(block).success).toBe(true);
		expect(DomainSettings.safeParse(block).success).toBe(true);
		expect(OrgSettings.safeParse(block).success).toBe(true);
	});

	it("rejects a secret name that does not carry the prefix, on every tier", () => {
		// Without this, a settings write names any secret it likes and the
		// dispatch POSTs its value to an attacker-chosen endpoint. Same threat
		// the RELAY_CREDS_ prefix closed in #615.
		const evil = { newEmailWebhook: { enabled: true, urlSecret: "CONFIRMATION_TOKEN_SECRET" } };
		expect(MailboxSettings.safeParse(evil).success).toBe(false);
		expect(DomainSettings.safeParse(evil).success).toBe(false);
		expect(OrgSettings.safeParse(evil).success).toBe(false);
	});

	it("rejects an empty secret name", () => {
		expect(
			MailboxSettings.safeParse({ newEmailWebhook: { urlSecret: "" } }).success,
		).toBe(false);
	});

	it("accepts a block with fields omitted", () => {
		expect(MailboxSettings.safeParse({ newEmailWebhook: {} }).success).toBe(true);
	});

	it("exports the prefix the live global secret already satisfies", () => {
		expect(NEW_EMAIL_WEBHOOK_SECRET_PREFIX).toBe("NEW_EMAIL_WEBHOOK_");
		expect("NEW_EMAIL_WEBHOOK_URL".startsWith(NEW_EMAIL_WEBHOOK_SECRET_PREFIX)).toBe(true);
	});
});

describe("parseSettingsLenient — newEmailWebhook salvage", () => {
	it("drops an invalid newEmailWebhook block but preserves the rest of the tier", async () => {
		// Without this the strict parse fails on the whole object and the tier
		// falls back to `{}` on read, silently wiping `security` overrides.
		const { parseSettingsLenient } = await import("../../shared/mailbox-settings");
		const parsed = parseSettingsLenient(DomainSettings, {
			agentModel: "custom-model",
			newEmailWebhook: { enabled: true, urlSecret: "HUB_API_KEY" },
		});
		expect(parsed.agentModel).toBe("custom-model");
		// Muted, NOT dropped: dropping would read back as "inherit" and fall
		// through to the wider channel. See the fail-closed tests below.
		expect(parsed.newEmailWebhook).toEqual({ enabled: false });
	});

	it("salvages the mailbox tier too", async () => {
		const { parseSettingsLenient } = await import("../../shared/mailbox-settings");
		const parsed = parseSettingsLenient(MailboxSettings, {
			agentModel: "custom-model",
			newEmailWebhook: { enabled: true, urlSecret: "CONFIRMATION_TOKEN_SECRET" },
		});
		expect(parsed.agentModel).toBe("custom-model");
		expect(parsed.newEmailWebhook).toEqual({ enabled: false });
	});
});

describe("stripDefaultEqual: newEmailWebhook", () => {
	it("strips an empty block", async () => {
		const { stripDefaultEqual } = await import("../../workers/lib/mailbox-settings");
		expect(stripDefaultEqual({ newEmailWebhook: {} })).toEqual({});
	});

	it("PRESERVES an explicitly disabled block, unlike relay", async () => {
		// `{enabled:false}` is a mute, not a default. Absent means "inherit /
		// fall back to the global secret"; disabled means "this scope stays
		// silent". Stripping the mute on write would resurrect the block as
		// absent on the next read and quietly route the muted mailbox's mail
		// to the wider channel — the exact failure the resolver guards.
		const muted = { newEmailWebhook: { enabled: false } };
		expect(stripDefaultEqual(muted)).toEqual(muted);
	});

	it("keeps a configured block", async () => {
		const v = { newEmailWebhook: { enabled: true, urlSecret: MAILBOX_SECRET } };
		expect(stripDefaultEqual(v)).toEqual(v);
	});
});

describe("salvage + resolve — fail-closed on an invalid tier block", () => {
	/**
	 * Regression for the fail-open hole found in review of PR #694.
	 *
	 * Dropping an invalid block is fail-CLOSED for `relay`/`sidecar`, where
	 * absent means "off". It is fail-OPEN here, because absent means "inherit,
	 * else the global NEW_EMAIL_WEBHOOK_URL". A typo'd secret name at the
	 * winning tier would therefore route that scope's mail to the wider
	 * channel the tier was configured to replace.
	 *
	 * Exercises the REAL parse → resolve chain. The receiveEmail-level tests
	 * mock `resolveMailboxSettings` wholesale, so they never touch salvage.
	 */
	it("mutes rather than inherits when the winning tier's block was salvaged away", async () => {
		const { parseSettingsLenient } = await import("../../shared/mailbox-settings");
		// A hand-edited R2 blob — the Zod write path rejects this name.
		const mailboxTier = parseSettingsLenient(MailboxSettings, {
			agentModel: "custom-model",
			newEmailWebhook: { enabled: true, urlSecret: "NEW_EMAIL_WEBHOK_GROK" },
		});
		expect(mailboxTier.agentModel).toBe("custom-model");

		expect(resolveNewEmailWebhook({ raw: mailboxTier })).toEqual({
			configured: true,
			secretName: null,
			format: "chat",
		});
	});

	it("does not let a salvaged mailbox tier fall through to a configured org tier", async () => {
		const { parseSettingsLenient } = await import("../../shared/mailbox-settings");
		const mailboxTier = parseSettingsLenient(MailboxSettings, {
			newEmailWebhook: { enabled: true, urlSecret: "HUB_API_KEY" },
		});

		expect(
			resolveNewEmailWebhook({
				raw: mailboxTier,
				org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET } },
			}),
		).toEqual({ configured: true, secretName: null, format: "chat" });
	});
});

describe("resolveNewEmailWebhook — payload format", () => {
	it("defaults to chat so existing deployments are unchanged", () => {
		expect(
			resolveNewEmailWebhook({ org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET } } }).format,
		).toBe("chat");
		// The global-fallback path has no settings block at all.
		expect(resolveNewEmailWebhook({}).format).toBe("chat");
	});

	it("carries the winning tier's format", () => {
		expect(
			resolveNewEmailWebhook({
				org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET, format: "json" } },
			}).format,
		).toBe("json");
	});

	it("takes format from the winning tier only, never merging across tiers", () => {
		// Whole-object replace: a mailbox block that omits `format` gets the
		// default, NOT the org's json. Same contract as every other field here.
		expect(
			resolveNewEmailWebhook({
				raw: { newEmailWebhook: { enabled: true, urlSecret: MAILBOX_SECRET } },
				org: { newEmailWebhook: { enabled: true, urlSecret: ORG_SECRET, format: "json" } },
			}),
		).toEqual({ configured: true, secretName: MAILBOX_SECRET, format: "chat" });
	});

	it("accepts format on every tier schema and rejects an unknown value", () => {
		const ok = { newEmailWebhook: { enabled: true, urlSecret: MAILBOX_SECRET, format: "json" } };
		expect(MailboxSettings.safeParse(ok).success).toBe(true);
		expect(DomainSettings.safeParse(ok).success).toBe(true);
		expect(OrgSettings.safeParse(ok).success).toBe(true);
		expect(
			MailboxSettings.safeParse({ newEmailWebhook: { format: "xml" } }).success,
		).toBe(false);
	});
});
