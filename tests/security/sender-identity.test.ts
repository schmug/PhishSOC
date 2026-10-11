import { describe, expect, it } from "vitest";
import { authenticatedSender } from "../../workers/security/sender-identity";

describe("authenticatedSender", () => {
	it("accepts a plain single addr-spec when the domain matches header.from", () => {
		expect(authenticatedSender("user@allowed.example", { headerFrom: "allowed.example" })).toEqual({
			address: "user@allowed.example",
			domain: "allowed.example",
		});
	});

	it("accepts a subdomain address when header.from is that subdomain", () => {
		expect(authenticatedSender("u@mail.allowed.example", { headerFrom: "mail.allowed.example" })).toEqual({
			address: "u@mail.allowed.example",
			domain: "mail.allowed.example",
		});
	});

	it("rejects when the address domain differs from header.from", () => {
		expect(authenticatedSender("a@allowed.example", { headerFrom: "attacker.example" })).toBeNull();
	});

	it.each([
		'"a@allowed.example"@attacker.example', // postal-mime yields a@allowed.example@attacker.example
		"a@allowed.example@attacker.example",
		'"a@allowed.example"@attacker.example"',
		"a@allowed.example, b@attacker.example",
		"a@allowed.example <b@attacker.example>",
		"a @allowed.example",
		"a@allowed example",
	])("rejects a non-single-addr-spec: %j", (addr) => {
		expect(authenticatedSender(addr, { headerFrom: "allowed.example" })).toBeNull();
	});

	it.each(["a@.allowed.example", "a@allowed..example", "a@", "a@."])(
		"rejects a malformed domain: %j",
		(addr) => {
			expect(authenticatedSender(addr, {})).toBeNull();
		},
	);

	it("normalizes a trailing root dot on the address domain and header.from", () => {
		expect(authenticatedSender("u@allowed.example.", { headerFrom: "allowed.example" })).toEqual({
			address: "u@allowed.example.",
			domain: "allowed.example",
		});
		expect(authenticatedSender("u@allowed.example", { headerFrom: "allowed.example." })).toEqual({
			address: "u@allowed.example",
			domain: "allowed.example",
		});
	});

	it("returns the shape-checked identity when header.from is absent (caller decides trust)", () => {
		// Hard-allow rejects this itself (it requires header.from); the honeypot
		// owned-domain guard relies on this shape-only identity.
		expect(authenticatedSender("colleague@acme.example", {})).toEqual({
			address: "colleague@acme.example",
			domain: "acme.example",
		});
	});
});
