// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";

import {
	computeHarvestAlerts,
	DEFAULT_HARVEST_ALERT_CONFIG,
	resolveAlertConfig,
	type AlertDebounceStore,
	type HarvestAlertConfig,
	type ProbeRollupEntry,
} from "../../workers/intel/catchall-alert";

// ── In-memory AlertDebounceStore ──────────────────────────────────────────────

/** Record shape stored in the fake — tracks when an alert was last recorded. */
interface AlertRecord {
	alertedAt: string;
	distinctCount: number;
}

/**
 * Fake debounce store backed by a plain Map. `getLastAlertTime` replicates the
 * window-expiry check that the real `CatchallIntelDO` implementation will do.
 */
function makeDebounceStore(): AlertDebounceStore & {
	_alerts: Map<string, AlertRecord>;
} {
	const _alerts = new Map<string, AlertRecord>();

	return {
		_alerts,

		async getLastAlertTime(
			sourceIp: string,
			senderDomain: string,
			windowMinutes: number,
		): Promise<string | null> {
			const key = `${sourceIp}|${senderDomain}`;
			const record = _alerts.get(key);
			if (!record) return null;
			const cutoff = new Date(
				new Date(record.alertedAt).getTime() + windowMinutes * 60_000,
			);
			const now = new Date();
			return now < cutoff ? record.alertedAt : null;
		},

		async recordAlertTime(
			sourceIp: string,
			senderDomain: string,
			alertedAt: string,
			distinctCount: number,
		): Promise<void> {
			_alerts.set(`${sourceIp}|${senderDomain}`, { alertedAt, distinctCount });
		},
	};
}

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeRollup(overrides: Partial<ProbeRollupEntry> = {}): ProbeRollupEntry {
	return {
		source_ip: "1.2.3.4",
		sender_domain: "spam.example",
		count: 200,
		distinct_localparts: 100,
		max_score: 75,
		first_seen: "2026-06-05T10:00:00Z",
		last_seen: "2026-06-05T10:30:00Z",
		...overrides,
	};
}

const defaultConfig: HarvestAlertConfig = {
	threshold: 50,
	window_minutes: 60,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("computeHarvestAlerts", () => {
	it("returns no alerts for an empty rollup list", async () => {
		const store = makeDebounceStore();
		const alerts = await computeHarvestAlerts([], defaultConfig, store);
		expect(alerts).toEqual([]);
	});

	it("returns no alert when distinct_localparts is below threshold", async () => {
		const store = makeDebounceStore();
		const rollup = makeRollup({ distinct_localparts: 49 });
		const alerts = await computeHarvestAlerts([rollup], defaultConfig, store);
		expect(alerts).toEqual([]);
	});

	it("returns no alert when distinct_localparts equals threshold minus 1", async () => {
		const store = makeDebounceStore();
		const rollup = makeRollup({ distinct_localparts: defaultConfig.threshold - 1 });
		const alerts = await computeHarvestAlerts([rollup], defaultConfig, store);
		expect(alerts).toHaveLength(0);
	});

	it("raises an alert when distinct_localparts meets the threshold", async () => {
		const store = makeDebounceStore();
		const rollup = makeRollup({ distinct_localparts: defaultConfig.threshold });
		const now = new Date("2026-06-05T12:00:00Z");
		const alerts = await computeHarvestAlerts([rollup], defaultConfig, store, now);

		expect(alerts).toHaveLength(1);
		expect(alerts[0]).toMatchObject({
			source_ip: "1.2.3.4",
			sender_domain: "spam.example",
			distinct_localpart_count: defaultConfig.threshold,
			triggered_at: now.toISOString(),
		});
	});

	it("raises an alert when distinct_localparts exceeds the threshold", async () => {
		const store = makeDebounceStore();
		const rollup = makeRollup({ distinct_localparts: 200 });
		const alerts = await computeHarvestAlerts([rollup], defaultConfig, store);
		expect(alerts).toHaveLength(1);
		expect(alerts[0].distinct_localpart_count).toBe(200);
	});

	it("debounces: does not raise a second alert within the window", async () => {
		const store = makeDebounceStore();
		const rollup = makeRollup({ distinct_localparts: 100 });

		// First call — should alert and record in the store with current time.
		const first = await computeHarvestAlerts([rollup], defaultConfig, store);
		expect(first).toHaveLength(1);

		// Second call immediately after — the recorded alert is within the 60-min
		// window so it should be debounced.
		const second = await computeHarvestAlerts([rollup], defaultConfig, store);
		expect(second).toHaveLength(0);
	});

	it("re-raises after the debounce window expires", async () => {
		const store = makeDebounceStore();
		const rollup = makeRollup({ distinct_localparts: 100 });

		// Seed an alert that is 61 minutes in the past (outside the 60-min window)
		const pastAlert = new Date(Date.now() - 61 * 60_000).toISOString();
		store._alerts.set("1.2.3.4|spam.example", {
			alertedAt: pastAlert,
			distinctCount: 100,
		});

		const alerts = await computeHarvestAlerts([rollup], defaultConfig, store);
		expect(alerts).toHaveLength(1);
	});

	it("alerts for multiple sources independently", async () => {
		const store = makeDebounceStore();
		const rollups = [
			makeRollup({ source_ip: "1.1.1.1", distinct_localparts: 60 }),
			makeRollup({ source_ip: "2.2.2.2", distinct_localparts: 80 }),
			makeRollup({ source_ip: "3.3.3.3", distinct_localparts: 10 }), // below threshold
		];

		const alerts = await computeHarvestAlerts(rollups, defaultConfig, store);
		expect(alerts).toHaveLength(2);
		expect(alerts.map((a) => a.source_ip).sort()).toEqual(["1.1.1.1", "2.2.2.2"]);
	});

	it("debounces each (source_ip, sender_domain) pair independently", async () => {
		const store = makeDebounceStore();
		const rollups = [
			makeRollup({ source_ip: "1.1.1.1", sender_domain: "spam.example", distinct_localparts: 60 }),
			makeRollup({ source_ip: "2.2.2.2", sender_domain: "spam.example", distinct_localparts: 80 }),
		];

		// First call — both alert
		await computeHarvestAlerts(rollups, defaultConfig, store);

		// Seed first IP as recently alerted; second IP is NOT seeded here but
		// was recorded in the first call. Both should be debounced.
		const second = await computeHarvestAlerts(rollups, defaultConfig, store);
		expect(second).toHaveLength(0);
	});

	it("records each alert in the debounce store", async () => {
		const store = makeDebounceStore();
		const rollup = makeRollup({ distinct_localparts: 75 });
		await computeHarvestAlerts([rollup], defaultConfig, store);

		const key = `${rollup.source_ip}|${rollup.sender_domain}`;
		expect(store._alerts.has(key)).toBe(true);
		expect(store._alerts.get(key)?.distinctCount).toBe(75);
	});

	it("alert payload includes correct fields", async () => {
		const store = makeDebounceStore();
		const rollup = makeRollup({
			source_ip: "10.0.0.1",
			sender_domain: "attacker.io",
			distinct_localparts: 123,
		});
		const now = new Date("2026-06-05T15:00:00Z");
		const [alert] = await computeHarvestAlerts([rollup], defaultConfig, store, now);

		expect(alert.source_ip).toBe("10.0.0.1");
		expect(alert.sender_domain).toBe("attacker.io");
		expect(alert.distinct_localpart_count).toBe(123);
		expect(alert.triggered_at).toBe("2026-06-05T15:00:00.000Z");
	});
});

describe("resolveAlertConfig", () => {
	it("returns defaults when settings is undefined", () => {
		expect(resolveAlertConfig(undefined)).toEqual(DEFAULT_HARVEST_ALERT_CONFIG);
	});

	it("returns defaults when neither alert field is set", () => {
		expect(resolveAlertConfig({ enabled: true })).toEqual(
			DEFAULT_HARVEST_ALERT_CONFIG,
		);
	});

	it("uses harvest_alert_threshold from settings", () => {
		const cfg = resolveAlertConfig({ harvest_alert_threshold: 25 });
		expect(cfg.threshold).toBe(25);
		expect(cfg.window_minutes).toBe(DEFAULT_HARVEST_ALERT_CONFIG.window_minutes);
	});

	it("uses harvest_alert_window_minutes from settings", () => {
		const cfg = resolveAlertConfig({ harvest_alert_window_minutes: 30 });
		expect(cfg.threshold).toBe(DEFAULT_HARVEST_ALERT_CONFIG.threshold);
		expect(cfg.window_minutes).toBe(30);
	});

	it("uses both fields from settings when both are present", () => {
		const cfg = resolveAlertConfig({
			harvest_alert_threshold: 10,
			harvest_alert_window_minutes: 120,
		});
		expect(cfg.threshold).toBe(10);
		expect(cfg.window_minutes).toBe(120);
	});
});

describe("CatchallIntelSettings schema round-trip", () => {
	it("parses a full catchall_intel block from DomainSettings", async () => {
		const { CatchallIntelSettings } = await import("../../shared/domain-settings");
		const input = {
			enabled: true,
			retention_days: 30,
			sample_limit: 50,
			harvest_alert_threshold: 50,
			harvest_alert_window_minutes: 60,
		};
		const result = CatchallIntelSettings.safeParse(input);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data).toMatchObject(input);
	});

	it("accepts an empty catchall_intel block (all fields optional)", async () => {
		const { CatchallIntelSettings } = await import("../../shared/domain-settings");
		const result = CatchallIntelSettings.safeParse({});
		expect(result.success).toBe(true);
	});

	it("rejects non-positive threshold", async () => {
		const { CatchallIntelSettings } = await import("../../shared/domain-settings");
		const result = CatchallIntelSettings.safeParse({ harvest_alert_threshold: 0 });
		expect(result.success).toBe(false);
	});

	it("rejects non-positive window_minutes", async () => {
		const { CatchallIntelSettings } = await import("../../shared/domain-settings");
		const result = CatchallIntelSettings.safeParse({ harvest_alert_window_minutes: -5 });
		expect(result.success).toBe(false);
	});

	it("round-trips through DomainSettings", async () => {
		const { parseDomainSettings } = await import("../../shared/domain-settings");
		const input = {
			catchall_intel: {
				enabled: false,
				harvest_alert_threshold: 75,
				harvest_alert_window_minutes: 120,
			},
		};
		const result = parseDomainSettings(input);
		expect(result).not.toBeNull();
		expect(result?.catchall_intel?.harvest_alert_threshold).toBe(75);
		expect(result?.catchall_intel?.harvest_alert_window_minutes).toBe(120);
	});
});
