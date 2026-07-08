// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { MailboxSettings, SidecarSettings } from "../../shared/mailbox-settings";
import { sidecarConfigOf, sidecarHealthOf } from "../../workers/lib/sidecar-config";
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

describe("sidecarHealthOf x last_gap (#594)", () => {
	it("reports last_gap: null when no gap event exists (and by default)", () => {
		expect(sidecarHealthOf(null).last_gap).toBeNull();
		expect(
			sidecarHealthOf({ consecutive_failures: 0, last_poll_at: Date.now(), last_error: null }, null).last_gap,
		).toBeNull();
	});

	it("surfaces the gap timestamp + cursor jump WITHOUT flipping healthy (gap ≠ failure)", () => {
		const h = sidecarHealthOf(
			{ consecutive_failures: 0, last_poll_at: Date.now(), last_error: null },
			{ ts: "2026-07-06T00:00:00Z", old_cursor: "100", new_cursor: "900" },
		);
		expect(h.healthy).toBe(true);
		expect(h.last_gap).toEqual({ ts: "2026-07-06T00:00:00Z", old_cursor: "100", new_cursor: "900" });
	});

	it("keeps last_gap to the surfaced shape even when the DO row carries extra columns", () => {
		const h = sidecarHealthOf(
			{ consecutive_failures: 0, last_poll_at: Date.now(), last_error: null },
			{ ts: "2026-07-06T00:00:00Z", old_cursor: "100", new_cursor: "900", kind: "history-gap", detail: "x" } as never,
		);
		expect(h.last_gap).toEqual({ ts: "2026-07-06T00:00:00Z", old_cursor: "100", new_cursor: "900" });
	});
});

describe("sidecarHealthOf x label_error (#590)", () => {
	const base = { consecutive_failures: 0, last_poll_at: Date.now(), last_error: null };

	it("a persisted label error flips healthy false and stays visible", () => {
		const h = sidecarHealthOf({ ...base, label_error: "label write failed for 1 message(s): 403" });
		expect(h.healthy).toBe(false);
		expect(h.label_error).toBe("label write failed for 1 message(s): 403");
	});

	it("no label error → healthy (and label_error: null in the payload)", () => {
		const h = sidecarHealthOf({ ...base, label_error: null });
		expect(h.healthy).toBe(true);
		expect(h.label_error).toBeNull();
	});

	it("tolerates pre-#590 state rows without the column (and the null state)", () => {
		expect(sidecarHealthOf(base).healthy).toBe(true);
		expect(sidecarHealthOf(base).label_error).toBeNull();
		expect(sidecarHealthOf(null).label_error).toBeNull();
	});

	it("label error flips healthy even when the poll counters look clean — the point-a flap", () => {
		// The exact regression: a label-clean poll reset consecutive_failures/
		// last_error, so health flapped green while the DWD grant stayed wrong.
		const h = sidecarHealthOf({
			consecutive_failures: 0,
			last_poll_at: Date.now(),
			last_error: null,
			label_error: "label write failed for 3 message(s): insufficient scope",
		});
		expect(h.healthy).toBe(false);
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
