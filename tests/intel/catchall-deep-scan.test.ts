// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for `runCatchallDeepScan` (issue #438).
 *
 * Drives the deep-scan with injected RDAP / redirect implementations so the
 * write-back logic is exercised without the network. Covers:
 *   - both enrichments succeed → result + write-back carry all three fields
 *   - no URL → redirect fields null, domain age still resolved
 *   - an enrichment that throws degrades to null (best-effort, no throw)
 *   - the deep-scan only ever calls updateProbeDeepScan (no MailboxDO access)
 */

import { describe, expect, it, vi } from "vitest";
import { runCatchallDeepScan } from "../../workers/intel/catchall-deep-scan";

function makeStub() {
	return { updateProbeDeepScan: vi.fn().mockResolvedValue(undefined) };
}

describe("runCatchallDeepScan", () => {
	it("resolves RDAP age + redirect chain and writes all three fields back", async () => {
		const stub = makeStub();
		const result = await runCatchallDeepScan(
			{ sampleId: "sample-1", senderDomain: "attacker.example", url: "http://t.co/abc" },
			{
				stub,
				lookupDomainAge: async () => ({ age_days: 3 }),
				resolveUrl: async () => ({ resolved: "https://phish.example/final", hops: 2 }),
			},
		);

		expect(result).toEqual({
			resolved_url: "https://phish.example/final",
			domain_age_days: 3,
			redirect_chain_length: 2,
		});
		expect(stub.updateProbeDeepScan).toHaveBeenCalledOnce();
		expect(stub.updateProbeDeepScan).toHaveBeenCalledWith("sample-1", result);
	});

	it("skips redirect resolution when there is no URL (age still resolved)", async () => {
		const stub = makeStub();
		const resolveSpy = vi.fn();
		const result = await runCatchallDeepScan(
			{ sampleId: "sample-2", senderDomain: "attacker.example", url: null },
			{ stub, lookupDomainAge: async () => ({ age_days: 10 }), resolveUrl: resolveSpy },
		);

		expect(resolveSpy).not.toHaveBeenCalled();
		expect(result).toEqual({
			resolved_url: null,
			domain_age_days: 10,
			redirect_chain_length: null,
		});
	});

	it("skips the RDAP lookup when there is no sender domain", async () => {
		const stub = makeStub();
		const ageSpy = vi.fn();
		const result = await runCatchallDeepScan(
			{ sampleId: "sample-3", senderDomain: "", url: "http://t.co/x" },
			{ stub, lookupDomainAge: ageSpy, resolveUrl: async () => ({ resolved: "https://x.example", hops: 1 }) },
		);

		expect(ageSpy).not.toHaveBeenCalled();
		expect(result.domain_age_days).toBeNull();
		expect(result.redirect_chain_length).toBe(1);
	});

	it("degrades to null when an enrichment throws (best-effort, still writes back)", async () => {
		const stub = makeStub();
		const result = await runCatchallDeepScan(
			{ sampleId: "sample-4", senderDomain: "attacker.example", url: "http://t.co/x" },
			{
				stub,
				lookupDomainAge: async () => {
					throw new Error("rdap down");
				},
				resolveUrl: async () => {
					throw new Error("resolve down");
				},
			},
		);

		expect(result).toEqual({
			resolved_url: null,
			domain_age_days: null,
			redirect_chain_length: null,
		});
		expect(stub.updateProbeDeepScan).toHaveBeenCalledOnce();
	});
});
