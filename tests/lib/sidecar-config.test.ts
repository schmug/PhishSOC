// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { MailboxSettings, SidecarSettings } from "../../shared/mailbox-settings";
import { sidecarConfigOf } from "../../workers/lib/sidecar-config";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("SidecarSettings schema", () => {
	it("accepts a minimal valid block", () => {
		const r = SidecarSettings.safeParse({
			provider: "workspace",
			credentials_secret_name: "SIDECAR_SECRET_acme",
		});
		expect(r.success).toBe(true);
	});

	it("rejects a secret name without the SIDECAR_SECRET_ prefix", () => {
		const r = SidecarSettings.safeParse({
			provider: "workspace",
			credentials_secret_name: "HUB_SECRET_acme",
		});
		expect(r.success).toBe(false);
	});

	it("rejects unknown providers", () => {
		const r = SidecarSettings.safeParse({
			provider: "m365",
			credentials_secret_name: "SIDECAR_SECRET_acme",
		});
		expect(r.success).toBe(false);
	});

	it("round-trips through MailboxSettings", () => {
		const r = MailboxSettings.safeParse({
			sidecar: {
				provider: "workspace",
				credentials_secret_name: "SIDECAR_SECRET_acme",
				mode: "active",
				retention_days: 30,
			},
		});
		expect(r.success).toBe(true);
		if (r.success) expect(r.data.sidecar?.mode).toBe("active");
	});

	it("rejects negative retention_days", () => {
		const r = SidecarSettings.safeParse({
			provider: "workspace",
			credentials_secret_name: "SIDECAR_SECRET_acme",
			retention_days: -1,
		});
		expect(r.success).toBe(false);
	});
});

describe("sidecarConfigOf", () => {
	it("returns null when the settings have no sidecar block", () => {
		expect(sidecarConfigOf({})).toBeNull();
		expect(sidecarConfigOf(undefined)).toBeNull();
		expect(sidecarConfigOf(null)).toBeNull();
	});

	it("returns null on an invalid block (bad prefix) instead of throwing", () => {
		expect(
			sidecarConfigOf({ sidecar: { provider: "workspace", credentials_secret_name: "nope" } }),
		).toBeNull();
	});

	it("applies defaults: observe, label-only, 7-day retention", () => {
		const cfg = sidecarConfigOf({
			sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_acme" },
		});
		expect(cfg).toEqual({
			provider: "workspace",
			credentials_secret_name: "SIDECAR_SECRET_acme",
			mode: "observe",
			quarantine_behavior: "label-only",
			retention_days: 7,
		});
	});

	it("preserves explicit values including retention_days 0 (keep forever)", () => {
		const cfg = sidecarConfigOf({
			sidecar: {
				provider: "workspace",
				credentials_secret_name: "SIDECAR_SECRET_acme",
				mode: "active",
				quarantine_behavior: "label-and-archive",
				retention_days: 0,
			},
		});
		expect(cfg?.mode).toBe("active");
		expect(cfg?.quarantine_behavior).toBe("label-and-archive");
		expect(cfg?.retention_days).toBe(0);
	});
});

describe("stripDefaultEqual x sidecar", () => {
	it("passes the sidecar block through untouched (no system default to strip against)", () => {
		const input = {
			sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_acme" },
		};
		const out = stripDefaultEqual(input as Record<string, unknown>);
		expect(out.sidecar).toEqual(input.sidecar);
	});
});
