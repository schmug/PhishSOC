// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Consolidated date formatting utilities.
 *
 * Previously spread across `app/lib/utils.ts` (4 functions) and
 * `workers/lib/html.ts` (`formatEmailDate`). Now one canonical set
 * imported by both the frontend and backend.
 */

/** Parse safely — returns null on invalid dates instead of NaN-date. */
function safeParse(dateStr: string | undefined | null): number | null {
	if (!dateStr) return null;
	const ms = Date.parse(dateStr);
	return Number.isNaN(ms) ? null : ms;
}

// ⚡ Bolt: Cache Intl.DateTimeFormat instances to prevent expensive instantiations
// inside loops (e.g. mapping over a large list of emails).
const listTimeFormatter = new Intl.DateTimeFormat(undefined, {
	hour: "numeric",
	minute: "2-digit",
});

const listDateThisYearFormatter = new Intl.DateTimeFormat(undefined, {
	month: "short",
	day: "numeric",
});

const listDateOlderFormatter = new Intl.DateTimeFormat(undefined, {
	month: "short",
	day: "numeric",
	year: "numeric",
});

const detailDateFormatter = new Intl.DateTimeFormat(undefined, {
	weekday: "short",
	month: "short",
	day: "numeric",
	hour: "numeric",
	minute: "2-digit",
});

const shortDateFormatter = new Intl.DateTimeFormat(undefined, {
	hour: "numeric",
	minute: "2-digit",
});

const quotedDateFormatter = new Intl.DateTimeFormat("en-US", {
	weekday: "short",
	month: "short",
	day: "numeric",
	year: "numeric",
	hour: "numeric",
	minute: "2-digit",
	hour12: true,
});

const standardDateFormatter = new Intl.DateTimeFormat(undefined, {
	dateStyle: "medium",
	timeStyle: "medium",
});

let _lastNowMs = 0;
let _lastNowMidnightMs = 0;
let _lastNowMidnightNextMs = 0;
let _lastNowYearStartMs = 0;
let _lastNowYearEndMs = 0;

/**
 * Email list rows.
 * - Today: "3:42 PM"
 * - This year: "Apr 15"
 * - Older: "Apr 15, 2024"
 */
export function formatListDate(dateStr: string): string {
	// ⚡ Bolt: Use Date.parse() instead of new Date() to avoid object allocation in render loops
	const ms = safeParse(dateStr);
	// strict null check because Date.parse("1970-01-01T00:00:00Z") === 0
	if (ms === null) return dateStr;

	const nowMs = Date.now();
	// ⚡ Bolt: Cache current date properties to avoid expensive new Date() calls on every format execution.
	// Math.abs handles time-travel in tests (e.g. mock timers resetting the clock).
	if (Math.abs(nowMs - _lastNowMs) > 1000) {
		const now = new Date(nowMs);
		// Note: using local time Date constructor to let the runtime handle DST transitions
		_lastNowMidnightMs = new Date(
			now.getFullYear(),
			now.getMonth(),
			now.getDate(),
		).getTime();
		_lastNowMidnightNextMs = new Date(
			now.getFullYear(),
			now.getMonth(),
			now.getDate() + 1,
		).getTime();
		_lastNowYearStartMs = new Date(now.getFullYear(), 0, 1).getTime();
		_lastNowYearEndMs = new Date(now.getFullYear() + 1, 0, 1).getTime();
		_lastNowMs = nowMs;
	}

	// ⚡ Bolt: Use fast numerical comparisons instead of string allocations/Date methods
	// If the timestamp is today (bounded between midnight today and midnight tomorrow)
	if (ms >= _lastNowMidnightMs && ms < _lastNowMidnightNextMs) {
		return listTimeFormatter.format(ms);
	}

	// Fast check for this year without allocating a Date object
	if (ms >= _lastNowYearStartMs && ms < _lastNowYearEndMs) {
		return listDateThisYearFormatter.format(ms);
	}

	return listDateOlderFormatter.format(ms);
}

/**
 * Email detail header.
 * "Tue, Apr 15, 3:42 PM"
 */
export function formatDetailDate(dateStr: string): string {
	const ms = safeParse(dateStr);
	if (ms === null) return dateStr;

	return detailDateFormatter.format(ms);
}

/**
 * Thread message headers — time only.
 * "3:42 PM"
 */
export function formatShortDate(dateStr: string): string {
	const ms = safeParse(dateStr);
	if (ms === null) return dateStr;

	return shortDateFormatter.format(ms);
}

/**
 * Compose quoted replies & backend quoted blocks.
 * "Tue, Apr 15, 2026, 3:42 PM"
 *
 * Uses explicit "en-US" locale for deterministic output on both browser
 * and Cloudflare Workers (which support `toLocaleString`).
 */
export function formatQuotedDate(dateStr: string | undefined): string {
	if (!dateStr) return "";
	const ms = safeParse(dateStr);
	if (ms === null) return dateStr;

	return quotedDateFormatter.format(ms);
}

/**
 * Standard date formatting, matching default `toLocaleString()`.
 * Use this to avoid `new Date().toLocaleString()` overhead in renders.
 */
export function formatStandardDate(dateStr: string | number): string {
	if (typeof dateStr === "number") {
		return standardDateFormatter.format(dateStr);
	}
	const ms = safeParse(dateStr);
	if (ms === null) return dateStr;

	return standardDateFormatter.format(ms);
}
