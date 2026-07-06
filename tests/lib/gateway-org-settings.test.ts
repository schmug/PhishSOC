import { describe, expect, it } from "vitest";
import { OrgSettings } from "../../shared/org-settings";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("OrgSettings.gateway", () => {
	it("accepts ARC sealer config", () => {
		const parsed = OrgSettings.safeParse({
			gateway: { arcSealerDomain: "gw.example.com", arcSelector: "arc1" },
		});
		expect(parsed.success).toBe(true);
		expect(parsed.success && parsed.data.gateway?.arcSelector).toBe("arc1");
	});

	it("strips an empty gateway block, keeps a configured one", () => {
		expect(stripDefaultEqual({ gateway: {} })).toEqual({});
		const v = { gateway: { arcSealerDomain: "gw.example.com" } };
		expect(stripDefaultEqual(v)).toEqual(v);
	});
});
