// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Minimal Gmail REST client for the Workspace sidecar provider (issue #31).
 *
 * Auth is a Google service account with domain-wide delegation (DWD): we
 * sign an RS256 JWT assertion with the account's private key, setting
 * `sub` to the monitored user, and exchange it at the OAuth token endpoint
 * for a ~1h access token. Workers-runtime only: crypto.subtle, no node:.
 *
 * Scope is gmail.modify (read + label writes). Observe-only tenants may
 * grant gmail.readonly instead; label writes will then 403 until the DWD
 * grant is widened — see docs/sidecar-credentials.md.
 */

export const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me";

export interface ServiceAccount {
	client_email: string;
	private_key: string;
}

export class GmailApiError extends Error {
	constructor(
		public status: number,
		public body: string,
		message?: string,
	) {
		super(message ?? `Gmail API error ${status}: ${body.slice(0, 200)}`);
		this.name = "GmailApiError";
	}
}

export function parseServiceAccountJson(raw: unknown): ServiceAccount | null {
	if (typeof raw !== "string") return null;
	try {
		const parsed = JSON.parse(raw) as Partial<ServiceAccount>;
		if (typeof parsed.client_email !== "string" || !parsed.client_email) return null;
		if (typeof parsed.private_key !== "string" || !parsed.private_key.includes("PRIVATE KEY")) return null;
		return { client_email: parsed.client_email, private_key: parsed.private_key };
	} catch {
		return null;
	}
}

function b64url(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlJson(obj: unknown): string {
	return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
	const body = pem
		.replace(/-----BEGIN PRIVATE KEY-----/, "")
		.replace(/-----END PRIVATE KEY-----/, "")
		.replace(/\s+/g, "");
	const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
	return crypto.subtle.importKey(
		"pkcs8",
		der.buffer as ArrayBuffer,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		false,
		["sign"],
	);
}

/**
 * Exchange a DWD-signed JWT assertion for an access token impersonating
 * `impersonate`. Returns the token and its expiry (epoch ms, with a 60s
 * safety margin subtracted).
 */
export async function mintAccessToken(
	sa: ServiceAccount,
	impersonate: string,
): Promise<{ token: string; expiresAt: number }> {
	const iat = Math.floor(Date.now() / 1000);
	const header = b64urlJson({ alg: "RS256", typ: "JWT" });
	const claims = b64urlJson({
		iss: sa.client_email,
		sub: impersonate,
		scope: GMAIL_SCOPE,
		aud: TOKEN_URL,
		iat,
		exp: iat + 3600,
	});
	const signingInput = `${header}.${claims}`;
	const key = await importPrivateKey(sa.private_key);
	const sig = await crypto.subtle.sign(
		"RSASSA-PKCS1-v1_5",
		key,
		new TextEncoder().encode(signingInput),
	);
	const assertion = `${signingInput}.${b64url(new Uint8Array(sig))}`;

	const res = await fetch(TOKEN_URL, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
			assertion,
		}).toString(),
	});
	if (!res.ok) throw new GmailApiError(res.status, await res.text());
	const data = (await res.json()) as { access_token: string; expires_in: number };
	return {
		token: data.access_token,
		expiresAt: Date.now() + (data.expires_in - 60) * 1000,
	};
}
