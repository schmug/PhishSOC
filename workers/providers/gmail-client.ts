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

async function gmailFetch(token: string, pathAndQuery: string, init?: RequestInit): Promise<Response> {
	const res = await fetch(`${API_BASE}${pathAndQuery}`, {
		...init,
		headers: {
			Authorization: `Bearer ${token}`,
			...(init?.body ? { "Content-Type": "application/json" } : {}),
			...(init?.headers ?? {}),
		},
	});
	return res;
}

async function gmailJson<T>(token: string, pathAndQuery: string, init?: RequestInit): Promise<T> {
	const res = await gmailFetch(token, pathAndQuery, init);
	if (!res.ok) throw new GmailApiError(res.status, await res.text());
	return (await res.json()) as T;
}

export async function getProfile(token: string): Promise<{ emailAddress: string; historyId: string }> {
	const p = await gmailJson<{ emailAddress: string; historyId: string | number }>(token, "/profile");
	return { emailAddress: p.emailAddress, historyId: String(p.historyId) };
}

export type HistoryResult =
	| { ok: true; messageIds: string[]; historyId: string; truncated: boolean; nextPageToken?: string }
	| { ok: false; expired: true };

/** Gmail-internal labels that mark non-inbound messages we must never score. */
const SKIP_LABELS = new Set(["DRAFT", "SENT", "CHAT"]);
const MAX_HISTORY_PAGES = 3;

/**
 * List message ids added to INBOX since `startHistoryId`. A 404 means the
 * cursor is older than Gmail's history retention — the caller must
 * re-initialize from getProfile() and accept the gap.
 */
export async function listNewMessageIds(
	token: string,
	startHistoryId: string,
	resumePageToken?: string | null,
): Promise<HistoryResult> {
	const ids: string[] = [];
	const seen = new Set<string>();
	let latestHistoryId = startHistoryId;
	let pageToken: string | undefined = resumePageToken ?? undefined;
	// truncated = we stopped on the page cap with more pages still pending, so
	// the listing is INCOMPLETE. The caller must NOT advance the cursor on a
	// truncated result — otherwise the un-fetched tail is skipped forever.
	// When truncated, `nextPageToken` is the resume point for the next fetch.
	let truncated = false;
	let nextPageToken: string | undefined;
	for (let page = 0; page < MAX_HISTORY_PAGES; page++) {
		const qs = new URLSearchParams({
			startHistoryId,
			historyTypes: "messageAdded",
			labelId: "INBOX",
		});
		if (pageToken) qs.set("pageToken", pageToken);
		const res = await gmailFetch(token, `/history?${qs.toString()}`);
		if (res.status === 404) return { ok: false, expired: true };
		if (!res.ok) throw new GmailApiError(res.status, await res.text());
		const data = (await res.json()) as {
			historyId?: string | number;
			nextPageToken?: string;
			history?: Array<{ messagesAdded?: Array<{ message?: { id?: string; labelIds?: string[] } }> }>;
		};
		if (data.historyId !== undefined) latestHistoryId = String(data.historyId);
		for (const h of data.history ?? []) {
			for (const added of h.messagesAdded ?? []) {
				const m = added.message;
				if (!m?.id || seen.has(m.id)) continue;
				if ((m.labelIds ?? []).some((l) => SKIP_LABELS.has(l))) continue;
				seen.add(m.id);
				ids.push(m.id);
			}
		}
		if (!data.nextPageToken) break;
		pageToken = data.nextPageToken;
		// If this was the last iteration the loop allows but a page still
		// dangles, the listing is truncated by the page cap.
		if (page === MAX_HISTORY_PAGES - 1) {
			truncated = true;
			nextPageToken = data.nextPageToken;
		}
	}
	return {
		ok: true,
		messageIds: ids,
		historyId: latestHistoryId,
		truncated,
		...(nextPageToken ? { nextPageToken } : {}),
	};
}

export async function getRawMessage(token: string, id: string): Promise<Uint8Array> {
	const data = await gmailJson<{ raw: string }>(token, `/messages/${encodeURIComponent(id)}?format=raw`);
	const b64 = data.raw.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(data.raw.length / 4) * 4, "=");
	return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Resolve label names → ids, creating any that don't exist yet. `cached`
 * short-circuits everything when it already covers all names (the poller
 * persists the map in sidecar_state.label_ids).
 */
export async function ensureLabels(
	token: string,
	names: string[],
	cached: Record<string, string> | null,
): Promise<Record<string, string>> {
	if (cached && names.every((n) => typeof cached[n] === "string" && cached[n])) return cached;
	const listed = await gmailJson<{ labels?: Array<{ id: string; name: string }> }>(token, "/labels");
	const map: Record<string, string> = {};
	for (const l of listed.labels ?? []) map[l.name] = l.id;
	const out: Record<string, string> = {};
	for (const name of names) {
		if (map[name]) {
			out[name] = map[name];
			continue;
		}
		const created = await gmailJson<{ id: string }>(token, "/labels", {
			method: "POST",
			body: JSON.stringify({ name, labelListVisibility: "labelShow", messageListVisibility: "show" }),
		});
		out[name] = created.id;
	}
	return out;
}

export async function modifyMessage(
	token: string,
	id: string,
	addLabelIds: string[],
	removeLabelIds: string[],
): Promise<void> {
	await gmailJson(token, `/messages/${encodeURIComponent(id)}/modify`, {
		method: "POST",
		body: JSON.stringify({ addLabelIds, removeLabelIds }),
	});
}
