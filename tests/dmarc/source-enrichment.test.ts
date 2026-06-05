// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Regression guard for the #385 (label) + #386 (geo/ASN) enrichment interaction
 * on `dmarc_sources`.
 *
 * Both features enrich the same rows. At ingest the DO runs them sequenced in a
 * single waitUntil — label first (creates the row via INSERT OR IGNORE), then
 * geo. The risk this test pins down: geo must take its UPDATE branch on the
 * label-created row (asn still null) and must NOT take the else-INSERT branch,
 * which writes a `label: null` row that would shadow the PTR label forever.
 *
 * The DO can't be spun up in the node pool (no Workers runtime), so we invoke
 * the real `enrichDmarcSourcesGeo` method on the prototype with a fake `db`
 * that records which branch ran. `cloudflare:workers` is stubbed so MailboxDO
 * imports.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("cloudflare:workers", () => ({ DurableObject: class {} }));
vi.mock("../../workers/dmarc/geo", () => ({ lookupIpGeo: vi.fn() }));

import { MailboxDO } from "../../workers/durableObject/index";
import { lookupIpGeo } from "../../workers/dmarc/geo";

/**
 * Minimal stand-in for the drizzle db used by `enrichDmarcSourcesGeo`. `select`
 * returns the supplied existing rows; `update`/`insert` only record that they
 * ran (and with what), which is all the branch assertions need.
 */
function makeFakeDb(existing: Array<{ source_ip: string; asn: string | null }>) {
	const updates: Array<Record<string, unknown>> = [];
	const inserts: Array<Record<string, unknown>> = [];
	const db = {
		select: () => ({
			from: () => ({
				where: () => ({ all: () => existing }),
			}),
		}),
		update: () => ({
			set: (vals: Record<string, unknown>) => ({
				where: () => ({ run: () => updates.push(vals) }),
			}),
		}),
		insert: () => ({
			values: (vals: Record<string, unknown>) => ({
				onConflictDoNothing: () => ({ run: () => inserts.push(vals) }),
			}),
		}),
	};
	return { db, updates, inserts };
}

function runGeo(db: unknown, ips: string[]): Promise<void> {
	// `enrichDmarcSourcesGeo` only touches `this.db` + `lookupIpGeo`, so a bare
	// `{ db }` is a sufficient `this`.
	return (MailboxDO.prototype as unknown as {
		enrichDmarcSourcesGeo(this: { db: unknown }, ips: string[]): Promise<void>;
	}).enrichDmarcSourcesGeo.call({ db }, ips);
}

describe("enrichDmarcSourcesGeo (label + geo coexistence)", () => {
	beforeEach(() => vi.mocked(lookupIpGeo).mockReset());

	it("UPDATEs the label-created row instead of inserting a label-shadowing row", async () => {
		// Row already exists (label enrichment ran first) with asn still null.
		const { db, updates, inserts } = makeFakeDb([{ source_ip: "1.2.3.4", asn: null }]);
		vi.mocked(lookupIpGeo).mockResolvedValue({ asn: "AS15169 GOOGLE, US", country: "US" });

		await runGeo(db, ["1.2.3.4"]);

		// UPDATE branch, never the else-INSERT that would write label: null.
		expect(inserts).toHaveLength(0);
		expect(updates).toHaveLength(1);
		expect(updates[0]).toEqual({ asn: "AS15169 GOOGLE, US", country: "US" });
		// Geo must not touch `label` — the PTR label is preserved.
		expect(updates[0]).not.toHaveProperty("label");
	});

	it("skips rows already geo-enriched (asn present)", async () => {
		const { db, updates, inserts } = makeFakeDb([{ source_ip: "1.2.3.4", asn: "AS15169 GOOGLE, US" }]);
		vi.mocked(lookupIpGeo).mockResolvedValue({ asn: "AS15169 GOOGLE, US", country: "US" });

		await runGeo(db, ["1.2.3.4"]);

		expect(lookupIpGeo).not.toHaveBeenCalled();
		expect(updates).toHaveLength(0);
		expect(inserts).toHaveLength(0);
	});
});

describe("getNewDmarcSourceIps (legitimate-before-PTR race)", () => {
	function runGetNew(ipsByLabel: Map<string, string | null>, candidates: string[]): string[] {
		const sql = {
			exec: (query: string, ip: string) => {
				if (!query.includes("label")) return [];
				const label = ipsByLabel.get(ip);
				return label === undefined ? [] : [{ label }];
			},
		};
		return (MailboxDO.prototype as unknown as {
			getNewDmarcSourceIps(
				this: { ctx: { storage: { sql: typeof sql } } },
				candidates: string[],
			): string[];
		}).getNewDmarcSourceIps.call({ ctx: { storage: { sql } } }, candidates);
	}

	it("re-enriches when a legitimate toggle created a row before PTR ran", () => {
		const store = new Map<string, string | null>([["1.2.3.4", null]]);
		expect(runGetNew(store, ["1.2.3.4"])).toEqual(["1.2.3.4"]);
	});

	it("skips IPs that already have a PTR label", () => {
		const store = new Map<string, string | null>([["1.2.3.4", "Google"]]);
		expect(runGetNew(store, ["1.2.3.4"])).toEqual([]);
	});
});
