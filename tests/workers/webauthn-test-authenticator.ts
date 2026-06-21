// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// A minimal virtual WebAuthn authenticator for the #376 step-up tests. It
// generates a real ES256 (P-256) keypair via WebCrypto, exports the public key
// in COSE_Key form (what @simplewebauthn/server stores/verifies against), and
// produces spec-shaped assertions (authenticatorData + clientDataJSON + an
// ASN.1 DER ECDSA signature) so the server's verify path runs end-to-end
// against self-signed material — no fixtures, no mocked crypto.

function b64urlEncode(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
	const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
	const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

/** COSE_Key (CBOR) for an EC2 / ES256 / P-256 public key from its raw x,y. */
function coseEc2PublicKey(x: Uint8Array, y: Uint8Array): Uint8Array {
	const out: number[] = [];
	out.push(0xa5); // map(5)
	out.push(0x01, 0x02); // 1 (kty): 2 (EC2)
	out.push(0x03, 0x26); // 3 (alg): -7 (ES256)
	out.push(0x20, 0x01); // -1 (crv): 1 (P-256)
	out.push(0x21, 0x58, 0x20, ...x); // -2 (x): bstr(32)
	out.push(0x22, 0x58, 0x20, ...y); // -3 (y): bstr(32)
	return new Uint8Array(out);
}

/** WebCrypto returns raw r||s (IEEE P1363); authenticators emit ASN.1 DER. */
function rawSignatureToDer(raw: Uint8Array): Uint8Array {
	const encodeInt = (int: Uint8Array): number[] => {
		let i = 0;
		while (i < int.length - 1 && int[i] === 0) i++;
		let v = Array.from(int.slice(i));
		if (v[0] & 0x80) v = [0x00, ...v];
		return [0x02, v.length, ...v];
	};
	const r = encodeInt(raw.slice(0, 32));
	const s = encodeInt(raw.slice(32, 64));
	const body = [...r, ...s];
	return new Uint8Array([0x30, body.length, ...body]);
}

/** authenticatorData = rpIdHash(32) | flags(1) | signCount(4 BE). */
function authenticatorData(rpIdHash: Uint8Array, flags: number, counter: number): Uint8Array {
	const ad = new Uint8Array(37);
	ad.set(rpIdHash, 0);
	ad[32] = flags;
	ad[33] = (counter >>> 24) & 0xff;
	ad[34] = (counter >>> 16) & 0xff;
	ad[35] = (counter >>> 8) & 0xff;
	ad[36] = counter & 0xff;
	return ad;
}

export interface TestAuthenticator {
	credentialId: string;
	cosePublicKey: Uint8Array;
	/** Produce an AuthenticationResponseJSON for the given options challenge. */
	assert(params: {
		challenge: string;
		rpId: string;
		origin: string;
		counter: number;
		/** Default true (UV flag set). Pass false to simulate a UV-absent key. */
		userVerified?: boolean;
	}): Promise<Record<string, unknown>>;
}

export async function createTestAuthenticator(
	over: { credentialId?: string } = {},
): Promise<TestAuthenticator> {
	const { publicKey, privateKey } = await crypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		true,
		["sign", "verify"],
	);
	const jwk = await crypto.subtle.exportKey("jwk", publicKey);
	const cosePublicKey = coseEc2PublicKey(b64urlDecode(jwk.x!), b64urlDecode(jwk.y!));
	const credentialId =
		over.credentialId ?? b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));

	return {
		credentialId,
		cosePublicKey,
		async assert(params) {
			const UP = 0x01;
			const UV = 0x04;
			const flags = UP | (params.userVerified === false ? 0 : UV);
			const rpIdHash = await sha256(new TextEncoder().encode(params.rpId));
			const authData = authenticatorData(rpIdHash, flags, params.counter);
			const clientDataJSON = new TextEncoder().encode(
				JSON.stringify({
					type: "webauthn.get",
					challenge: params.challenge,
					origin: params.origin,
					crossOrigin: false,
				}),
			);
			const clientDataHash = await sha256(clientDataJSON);
			const signatureBase = new Uint8Array(authData.length + clientDataHash.length);
			signatureBase.set(authData, 0);
			signatureBase.set(clientDataHash, authData.length);
			const rawSig = new Uint8Array(
				await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, signatureBase),
			);
			return {
				id: credentialId,
				rawId: credentialId,
				type: "public-key",
				clientExtensionResults: {},
				response: {
					authenticatorData: b64urlEncode(authData),
					clientDataJSON: b64urlEncode(clientDataJSON),
					signature: b64urlEncode(rawSignatureToDer(rawSig)),
					userHandle: null,
				},
			};
		},
	};
}
