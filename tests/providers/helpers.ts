// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Shared test helpers for the Gmail sidecar provider tests (issue #31).
 * Extracted from tests/providers/gmail-client.test.ts so
 * tests/routes/sidecar-test-endpoint.test.ts (Task 9) can reuse the same
 * signing key instead of duplicating the RSA keypair generation.
 */

/** Generates a fresh RSA keypair and wraps the private key as a fake
 * Google service-account credential, plus the matching public key so
 * callers can verify the JWT assertion signed with it. */
export async function makeTestServiceAccount(): Promise<{
	sa: { client_email: string; private_key: string };
	publicKey: CryptoKey;
}> {
	const kp = await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	);
	const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
	const b64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
	const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
	return { sa: { client_email: "svc@proj.iam.gserviceaccount.com", private_key: pem }, publicKey: kp.publicKey };
}
