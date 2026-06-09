// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Business-hours / off-hours scoring contribution.
 *
 * BEC and wire-fraud attempts are disproportionately delivered outside of
 * the recipient's working hours (attacker presumes the CFO reading a wire
 * request at 7pm on a Friday won't double-check with treasury). This module
 * turns a mailbox-level `business_hours` setting into a small score nudge.
 *
 * DESIGN RULES:
 *   - Scoring only. Never short-circuits the pipeline. The triage layer
 *     deliberately ignores this signal — a legitimate sender emailing
 *     at 3 AM is still legitimate mail and must remain allow-able.
 *   - Off-hours boost is small (+10) so it can't single-handedly quarantine
 *     a clean email; it nudges borderline verdicts over the threshold.
 *   - Invalid timezone strings produce a zero contribution. We don't fail
 *     open by assuming UTC or anything else — silent timezone misconfig
 *     silently breaks the signal, which is the conservative default.
 */

import type { BusinessHours } from "./settings";

export interface TimeRuleResult {
	score: number;
	reasons: string[];
}

/**
 * `at` defaults to `new Date()` but is threaded as a parameter so tests can
 * inject a fixed instant without mocking the global clock.
 */
export function scoreOffHours(
	hours: BusinessHours | undefined,
	at: Date = new Date(),
): TimeRuleResult {
	if (!hours || !hours.boost_on_off_hours) return { score: 0, reasons: [] };

	const local = localDateParts(hours.timezone, at);
	if (!local) return { score: 0, reasons: [] };

	const { hour, weekday } = local;

	// weekday in the Intl.DateTimeFormat output is 0=Sunday..6=Saturday
	const isWeekend = weekday === 0 || weekday === 6;
	if (hours.weekdays_only && isWeekend) {
		return {
			score: 10,
			reasons: [`received on weekend (${hours.timezone})`],
		};
	}

	const start = clampHour(hours.start_hour, 7);
	const end = clampHour(hours.end_hour, 19);

	// Range is inclusive-start, exclusive-end so `end_hour = 19` treats 19:00
	// as off-hours. Handles wrapped windows (night-shift style, e.g. start=22,
	// end=6) for completeness even though BEC signal goes the other way.
	const inHours =
		start <= end ? hour >= start && hour < end : hour >= start || hour < end;

	if (inHours) return { score: 0, reasons: [] };
	return {
		score: 10,
		reasons: [
			`received outside business hours (${String(hour).padStart(2, "0")}:00 ${hours.timezone})`,
		],
	};
}

function clampHour(v: number, fallback: number): number {
	if (!Number.isFinite(v)) return fallback;
	const i = Math.floor(v);
	if (i < 0 || i > 23) return fallback;
	return i;
}

interface LocalParts {
	hour: number;
	weekday: number;
}

const FORMATTER_CACHE = new Map<string, Intl.DateTimeFormat>();

function localDateParts(timezone: string, at: Date): LocalParts | null {
	try {
		let fmt = FORMATTER_CACHE.get(timezone);
		if (!fmt) {
			// ⚡ Bolt: Cache Intl.DateTimeFormat instances keyed by timezone to prevent expensive instantiations
			fmt = new Intl.DateTimeFormat("en-US", {
				timeZone: timezone,
				hour: "numeric",
				hour12: false,
				weekday: "short",
			});
			FORMATTER_CACHE.set(timezone, fmt);
		}
		const parts = fmt.formatToParts(at);
		let hour = NaN;
		let weekdayName = "";
		for (const p of parts) {
			if (p.type === "hour") hour = parseInt(p.value, 10);
			else if (p.type === "weekday") weekdayName = p.value;
		}
		// Intl formats midnight as either "0" or "24" across locales/runtimes; normalise.
		if (hour === 24) hour = 0;
		if (!Number.isFinite(hour)) return null;
		const weekdayIndex = WEEKDAY_INDEX[weekdayName];
		if (weekdayIndex === undefined) return null;
		return { hour, weekday: weekdayIndex };
	} catch {
		return null;
	}
}

const WEEKDAY_INDEX: Record<string, number> = {
	Sun: 0,
	Mon: 1,
	Tue: 2,
	Wed: 3,
	Thu: 4,
	Fri: 5,
	Sat: 6,
};
