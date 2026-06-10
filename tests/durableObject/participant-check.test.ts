// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for the exact-address participant check used by
 * `findThreadBySubject` in `workers/durableObject/index.ts` (issue #463).
 *
 * The old implementation used `String.prototype.includes` which let a sender
 * whose address is a substring of a genuine participant's address bypass the
 * check.  The fix splits on the GROUP_CONCAT delimiter (`,`) and uses Set.has
 * for exact membership.
 */

import { describe, expect, it } from "vitest";

// Mock cloudflare:workers — MailboxDO extends DurableObject from this module
// but `_isKnownParticipant` is a standalone export that doesn't touch it.
import { vi } from "vitest";
vi.mock("cloudflare:workers", () => ({
	DurableObject: class {
		ctx: unknown;
		env: unknown;
		constructor(state: unknown, env: unknown) { this.ctx = state; this.env = env; }
	},
}));

import { _isKnownParticipant } from "../../workers/durableObject/index";

describe("_isKnownParticipant — exact-address match (issue #463)", () => {
	it("returns true for an exact address match in senders", () => {
		expect(_isKnownParticipant("alice@example.com,bob@example.com", "", "alice@example.com")).toBe(true);
	});

	it("returns true for an exact address match in recipients", () => {
		expect(_isKnownParticipant("", "carol@example.com,dave@example.com", "carol@example.com")).toBe(true);
	});

	it("returns false for a substring of a real sender address (old bug)", () => {
		// 'lice@example.com' is a substring of 'alice@example.com'
		// The old `includes` check would have returned true — this is the attack vector.
		expect(_isKnownParticipant("alice@example.com", "", "lice@example.com")).toBe(false);
	});

	it("returns false for a domain suffix that appears in real addresses", () => {
		expect(_isKnownParticipant("alice@example.com,bob@example.com", "", "example.com")).toBe(false);
	});

	it("returns false when sender is not in either list", () => {
		expect(_isKnownParticipant("alice@example.com", "bob@example.com", "eve@attacker.com")).toBe(false);
	});

	it("handles empty GROUP_CONCAT strings gracefully", () => {
		expect(_isKnownParticipant("", "", "alice@example.com")).toBe(false);
	});

	it("is case-sensitive (senders already lowercased by SQL LOWER())", () => {
		expect(_isKnownParticipant("alice@example.com", "", "Alice@Example.com")).toBe(false);
		expect(_isKnownParticipant("alice@example.com", "", "alice@example.com")).toBe(true);
	});
});
