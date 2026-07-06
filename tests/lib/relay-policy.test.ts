import { describe, expect, it } from "vitest";
import {
	DEFAULT_RELAY_ACTIONS,
	behaviorFor,
	resolveRelayPolicy,
} from "../../workers/lib/relay-policy";

const enabled = {
	relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } },
};

describe("resolveRelayPolicy", () => {
	it("returns null when relay is absent, disabled, or has no target host", () => {
		expect(resolveRelayPolicy({})).toBeNull();
		expect(resolveRelayPolicy({ relay: { enabled: false, target: { host: "h" } } })).toBeNull();
		expect(resolveRelayPolicy({ relay: { enabled: true } })).toBeNull();
		expect(resolveRelayPolicy({ relay: { enabled: true, target: {} } })).toBeNull();
	});

	it("applies defaults: port 587, STARTTLS, fail-closed action map", () => {
		const p = resolveRelayPolicy(enabled);
		expect(p).not.toBeNull();
		expect(p!.target).toEqual({ host: "smtp-relay.gmail.com", port: 587, implicitTls: false });
		expect(p!.actions).toEqual(DEFAULT_RELAY_ACTIONS);
		expect(DEFAULT_RELAY_ACTIONS).toEqual({
			allow: "relay",
			tag: "relay",
			quarantine: "hold",
			block: "drop",
		});
	});

	it("honours per-domain overrides", () => {
		const p = resolveRelayPolicy({
			relay: {
				enabled: true,
				target: { host: "h", port: 465, implicitTls: true },
				credentialsSecret: "RELAY_CREDS_X",
				actions: { quarantine: "relay" },
			},
		});
		expect(p!.target.port).toBe(465);
		expect(p!.target.implicitTls).toBe(true);
		expect(p!.credentialsSecret).toBe("RELAY_CREDS_X");
		expect(p!.actions.quarantine).toBe("relay"); // explicit override allowed
		expect(p!.actions.block).toBe("drop"); // untouched default
	});
});

describe("behaviorFor", () => {
	const p = resolveRelayPolicy(enabled)!;

	it("maps verdict actions through the policy table", () => {
		expect(behaviorFor("allow", p)).toBe("relay");
		expect(behaviorFor("tag", p)).toBe("relay");
		expect(behaviorFor("quarantine", p)).toBe("hold");
		expect(behaviorFor("block", p)).toBe("drop");
	});

	it("null verdict (scan skipped/failed) fails open to relay", () => {
		expect(behaviorFor(null, p)).toBe("relay");
	});

	it("passthrough degrades hold to relay (nothing to hold into)", () => {
		expect(behaviorFor("quarantine", p, { passthrough: true })).toBe("relay");
		expect(behaviorFor("block", p, { passthrough: true })).toBe("drop");
	});
});
