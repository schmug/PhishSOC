import { describe, expect, it } from "vitest";
import { DomainSettings, RelaySettings } from "../../shared/domain-settings";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("RelaySettings schema", () => {
	it("accepts a full relay block", () => {
		const parsed = DomainSettings.safeParse({
			relay: {
				enabled: true,
				target: { host: "smtp-relay.gmail.com", port: 587, implicitTls: false },
				credentialsSecret: "RELAY_CREDS_EXAMPLE_COM",
				actions: { quarantine: "relay" },
			},
		});
		expect(parsed.success).toBe(true);
		expect(parsed.success && parsed.data.relay?.target?.host).toBe("smtp-relay.gmail.com");
	});

	it("accepts an empty object (all fields optional)", () => {
		expect(RelaySettings.safeParse({}).success).toBe(true);
	});

	it("rejects invalid action behaviors and ports", () => {
		expect(RelaySettings.safeParse({ actions: { allow: "bounce" } }).success).toBe(false);
		expect(RelaySettings.safeParse({ target: { host: "h", port: 0 } }).success).toBe(false);
		expect(RelaySettings.safeParse({ target: { host: "h", port: 70000 } }).success).toBe(false);
	});

	it("rejects credentialsSecret without the RELAY_CREDS_ prefix", () => {
		const parsed = RelaySettings.safeParse({
			credentialsSecret: "SIDECAR_SECRET_acme",
		});
		expect(parsed.success).toBe(false);
		if (!parsed.success) {
			expect(parsed.error.issues[0].message).toBe(
				"Secret name must start with RELAY_CREDS_",
			);
		}
	});
});

describe("parseSettingsLenient — relay salvage", () => {
	it("drops an invalid relay block but preserves the rest of the domain tier", async () => {
		const { parseSettingsLenient } = await import("../../shared/mailbox-settings");
		const parsed = parseSettingsLenient(DomainSettings, {
			agentModel: "custom-model",
			relay: {
				enabled: true,
				target: { host: "smtp-relay.gmail.com" },
				credentialsSecret: "SIDECAR_SECRET_acme",
			},
		});
		expect(parsed.agentModel).toBe("custom-model");
		expect(parsed.relay).toBeUndefined();
	});
});

describe("stripDefaultEqual: relay", () => {
	it("strips a disabled/empty relay block", () => {
		expect(stripDefaultEqual({ relay: { enabled: false } })).toEqual({});
		expect(stripDefaultEqual({ relay: {} })).toEqual({});
	});

	it("keeps an enabled relay block", () => {
		const v = { relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } } };
		expect(stripDefaultEqual(v)).toEqual(v);
	});
});
