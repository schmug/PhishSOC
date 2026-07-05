// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { mergeOrgSettingsPut } from "../../workers/lib/org-settings";
import type { OrgSettings } from "../../shared/org-settings";

describe("mergeOrgSettingsPut — preserve server-managed keys", () => {
	it("keeps persisted domains when PUT carries a stale domains snapshot", () => {
		const current: OrgSettings = {
			domains: ["newco.example", "seed.example"],
			agentModel: "@cf/org/model",
		};
		const incoming: OrgSettings = {
			domains: ["seed.example"],
			agentModel: "@cf/updated/model",
		};
		const merged = mergeOrgSettingsPut(current, incoming);
		expect(merged.domains).toEqual(["newco.example", "seed.example"]);
		expect(merged.agentModel).toBe("@cf/updated/model");
	});

	it("drops domains from PUT when R2 has none", () => {
		const current: OrgSettings = { agentModel: "@cf/org/model" };
		const incoming: OrgSettings = {
			domains: ["stale.example"],
			agentModel: "@cf/updated/model",
		};
		const merged = mergeOrgSettingsPut(current, incoming);
		expect(merged).not.toHaveProperty("domains");
	});

	it("preserves intel.feeds when PUT omits them", () => {
		const feeds = [{ id: "custom-feed", url: "https://feeds.example.com/list" }];
		const current: OrgSettings = {
			intel: { feeds },
		};
		const incoming: OrgSettings = {
			agentModel: "@cf/updated/model",
		};
		const merged = mergeOrgSettingsPut(current, incoming);
		expect(merged.intel?.feeds).toEqual(feeds);
		expect(merged.agentModel).toBe("@cf/updated/model");
	});

	it("allows PUT to replace intel.feeds when explicitly provided", () => {
		const current: OrgSettings = {
			intel: { feeds: [{ id: "old", url: "https://old.example/feed" }] },
		};
		const incoming: OrgSettings = {
			intel: { feeds: [{ id: "new", url: "https://new.example/feed" }] },
		};
		const merged = mergeOrgSettingsPut(current, incoming);
		expect(merged.intel?.feeds).toEqual(incoming.intel?.feeds);
	});
});
