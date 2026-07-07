import { describe, expect, it, beforeAll } from "vitest";
// mailauth is Node-only — fine here (tests run in the Node pool), forbidden in workers/.
import { authenticate } from "mailauth";
import { hasExistingArcChain, latin1Encode, sealMessage } from "../../workers/lib/arc-seal";

const SEALER = "gw.example.com";
const SELECTOR = "arc1";

let privateKeyPem: string;
let publicKeyB64: string;

function pemWrap(label: string, b64: string): string {
	const lines = b64.match(/.{1,64}/g) ?? [];
	return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

beforeAll(async () => {
	// Generate a throwaway RSA-2048 keypair per run — nothing committed.
	const kp = await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	);
	const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
	const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
	privateKeyPem = pemWrap("PRIVATE KEY", b64(pkcs8));
	publicKeyB64 = b64(spki);
});

// DNS resolver stub for mailauth: serves our test public key for the
// sealer's selector record, NXDOMAIN for everything else. Parses names —
// never substring-matches (CodeQL rule).
async function resolver(name: string, rr: string): Promise<string[][]> {
	if (rr === "TXT" && name.toLowerCase() === `${SELECTOR}._domainkey.${SEALER}`) {
		return [[`v=DKIM1; k=rsa; p=${publicKeyB64}`]];
	}
	const err = new Error(`queryTxt ENOTFOUND ${name}`) as Error & { code: string };
	err.code = "ENOTFOUND";
	throw err;
}

const MESSAGE = [
	"Received: from mx.origin.test (mx.origin.test [192.0.2.1])",
	"\tby cf.example.net for <user@example.com>; Mon, 6 Jul 2026 10:00:00 +0000",
	"From: Sender <sender@origin.test>",
	"To: user@example.com",
	"Subject: gateway seal test",
	"Date: Mon, 6 Jul 2026 10:00:00 +0000",
	"Message-ID: <seal-test-1@origin.test>",
	"X-PhishPilot-Verdict: allow",
	"X-PhishPilot-Score: 5",
	"",
	"Hello from the gateway test.",
	"",
].join("\r\n");

const OPTS = () => ({
	auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
	sealerDomain: SEALER,
	selector: SELECTOR,
	privateKeyPem,
	now: 1_783_400_400,
});

describe("sealMessage", () => {
	it("produces a seal that mailauth independently validates as arc=pass", async () => {
		const raw = latin1Encode(MESSAGE);
		const block = await sealMessage(raw, OPTS());
		expect(block).not.toBeNull();
		expect(block).toMatch(/^ARC-Seal: i=1; a=rsa-sha256; cv=none;/);
		expect(block).toContain("ARC-Message-Signature: i=1;");
		expect(block).toContain(`ARC-Authentication-Results: i=1; ${SEALER};`);

		const sealed = block! + MESSAGE;
		const res = await authenticate(sealed, {
			resolver,
			ip: "192.0.2.1",
			helo: "mx.origin.test",
			sender: "sender@origin.test",
			disableBimi: true,
		});
		expect(res.arc?.status?.result).toBe("pass");
	});

	it("a tampered body fails mailauth ARC validation", async () => {
		const raw = latin1Encode(MESSAGE);
		const block = await sealMessage(raw, OPTS());
		const tampered = block! + MESSAGE.replace("Hello from", "Howdy from");
		const res = await authenticate(tampered, {
			resolver,
			ip: "192.0.2.1",
			helo: "mx.origin.test",
			sender: "sender@origin.test",
			disableBimi: true,
		});
		expect(res.arc?.status?.result).not.toBe("pass");
	});

	it("returns null when the message already carries an ARC chain", async () => {
		const withChain = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=x.test; s=s; b=abc\r\n" + MESSAGE;
		const raw = latin1Encode(withChain);
		expect(hasExistingArcChain(raw)).toBe(true);
		expect(await sealMessage(raw, OPTS())).toBeNull();
	});
});
