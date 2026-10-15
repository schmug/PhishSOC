// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { combinedSendBodyForRisk } from "../../shared/send-risk-body";

describe("combinedSendBodyForRisk", () => {
	it("returns html when only html is present", () => {
		expect(combinedSendBodyForRisk("<p>Hi</p>", null)).toBe("<p>Hi</p>");
	});

	it("returns text when only text is present", () => {
		expect(combinedSendBodyForRisk(null, "wire transfer")).toBe("wire transfer");
	});

	it("joins both parts when html and text differ", () => {
		expect(
			combinedSendBodyForRisk("<p>Benign</p>", "wire transfer $50,000"),
		).toBe("<p>Benign</p>\nwire transfer $50,000");
	});

	it("returns empty string when both are absent", () => {
		expect(combinedSendBodyForRisk(null, null)).toBe("");
	});
});
