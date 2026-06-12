// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Per-mailbox access-control list (#27).
 *
 * ACLs are stored at R2 key `mailboxes-acl/<mailboxId>.json` — separate
 * from the settings blob at `mailboxes/<mailboxId>.json` so a settings PUT
 * never clobbers them, and the existing `listMailboxes` prefix scan over
 * `mailboxes/` doesn't pick them up.
 *
 * Backwards-compat invariant: when no ACL blob exists (pre-#27 mailboxes or
 * single-user deploys without CF Access in front), `callerInAcl` returns
 * true — anyone admitted by the global CF Access policy retains full access.
 *
 * Group grants (#295): in addition to explicit email members, a mailbox can be
 * granted to Cloudflare Access groups by name. Groups are managed in the CF
 * Access dashboard; the group names stored here must match the names shown
 * there (e.g. "soc-analysts"). Group membership is sourced exclusively from
 * the `groups` claim in the verified CF Access JWT — never from a header.
 * Existing email-only ACL blobs remain valid; absent `groups` field === no
 * group grants.
 */

import { decodeJwt } from "jose";

export interface MailboxAcl {
	/** Email of the user who created the mailbox (lower-cased). */
	owner: string;
	/** All emails permitted to access the mailbox (always includes owner). */
	members: string[];
	/**
	 * CF Access group names whose members may access this mailbox (#295).
	 * Names must match the group names defined in the Cloudflare Access
	 * dashboard. Absent or empty means no group grants.
	 */
	groups?: string[];
}

/**
 * Decodes the `groups` claim from a CF Access JWT without re-verifying the
 * signature (the global CF Access middleware already verified it). Returns []
 * when the token is absent, malformed, or carries no groups claim.
 *
 * This is the only approved source of group membership — not any HTTP header.
 */
export function callerGroupsFromJwt(jwtToken: string | null | undefined): string[] {
	if (!jwtToken) return [];
	try {
		const payload = decodeJwt(jwtToken);
		const raw = payload["groups"];
		return Array.isArray(raw) ? raw.filter((g): g is string => typeof g === "string") : [];
	} catch {
		return [];
	}
}

function aclKey(mailboxId: string): string {
	return `mailboxes-acl/${mailboxId}.json`;
}

export async function readMailboxAcl(
	env: { BUCKET: R2Bucket },
	mailboxId: string,
): Promise<MailboxAcl | null> {
	const obj = await env.BUCKET.get(aclKey(mailboxId));
	if (!obj) return null;
	try {
		return await obj.json<MailboxAcl>();
	} catch {
		return null;
	}
}

export async function writeMailboxAcl(
	env: { BUCKET: R2Bucket },
	mailboxId: string,
	acl: MailboxAcl,
): Promise<void> {
	await env.BUCKET.put(aclKey(mailboxId), JSON.stringify(acl));
}

export async function deleteMailboxAcl(
	env: { BUCKET: R2Bucket },
	mailboxId: string,
): Promise<void> {
	await env.BUCKET.delete(aclKey(mailboxId));
}

/**
 * Returns true when the caller should be granted access to the mailbox.
 *
 * - `acl === null`: no ACL written yet → allow anyone (backwards-compat for
 *   pre-#27 mailboxes and single-user deploys).
 * - `callerEmail` falsy: FAIL CLOSED in production (f17) — a missing email
 *   means the verified JWT carried no `email` claim (service token, or a
 *   direct-to-origin request whose identity could not be established), and
 *   granting access there is the cross-tenant bypass. Only local dev
 *   (`isDev === true`, no CF Access in front) is allowed through.
 * - Otherwise: caller must appear in `acl.members` (case-insensitive) OR
 *   belong to one of the `acl.groups` listed (matched against `callerGroups`
 *   sourced from the verified CF Access JWT via `callerGroupsFromJwt`).
 */
export function callerInAcl(
	acl: MailboxAcl | null,
	callerEmail: string | null | undefined,
	callerGroups: string[] = [],
	isDev: boolean = false,
): boolean {
	if (acl === null) return true;
	if (!callerEmail) return isDev;
	const lower = callerEmail.toLowerCase();
	if (acl.members.some((m) => m.toLowerCase() === lower)) return true;
	if (acl.groups?.some((g) => callerGroups.includes(g))) return true;
	return false;
}

/**
 * Decodes the `email` claim from a CF Access JWT without re-verifying the
 * signature (the global CF Access middleware already verified it). Returns null
 * when the token is absent, malformed, or carries no string `email` claim
 * (e.g. a CF Access *service token*, which has no `email`).
 *
 * Identity for an authorization decision must be sourced from the verified
 * token — never from the `cf-access-authenticated-user-email` header, which is
 * decoupled from the JWT and forgeable on a direct-to-origin request.
 */
export function callerEmailFromJwt(jwtToken: string | null | undefined): string | null {
	if (!jwtToken) return null;
	try {
		const email = decodeJwt(jwtToken)["email"];
		return typeof email === "string" && email.length > 0 ? email : null;
	} catch {
		return null;
	}
}

/**
 * Extracts the EmailAgent instance name (the mailboxId) from an `/agents/*`
 * request path, or null when the path does not target the per-mailbox
 * EmailAgent. The Agents SDK routes EmailAgent under the kebab-cased class
 * name, i.e. `/agents/email-agent/<mailboxId>[/...]` (see
 * `camelCaseToKebabCase("EmailAgent")`). OrgAgent (`/agents/org-agent/...`) is
 * intentionally excluded — it exposes only aggregate data.
 */
export function emailAgentMailboxIdFromPath(pathname: string): string | null {
	const segments = pathname.split("/").filter(Boolean);
	if (segments[0] === "agents" && segments[1] === "email-agent" && segments[2]) {
		try {
			return decodeURIComponent(segments[2]);
		} catch {
			return segments[2];
		}
	}
	return null;
}

/**
 * Authorizes a caller for a mailbox from their CF Access JWT — the same ACL
 * boundary that `requireMailbox` (HTTP) and `verifyMailbox` (MCP) enforce, but
 * usable from a non-Hono entry point (the EmailAgent WebSocket/agent route).
 * Fails CLOSED in production when identity cannot be established.
 *
 * - No ACL blob → allow (backwards-compat: pre-#27 mailboxes / single-user).
 * - `isDev` → allow (local dev, no CF Access in front — matches `callerInAcl`).
 * - Production: require a verified-JWT email; a missing email (no token, or a
 *   service token with no `email` claim) is DENIED. Otherwise defer to
 *   `callerInAcl` for members + group grants.
 */
export async function callerAllowedForMailbox(
	env: { BUCKET: R2Bucket },
	mailboxId: string,
	jwtToken: string | null | undefined,
	isDev: boolean,
): Promise<boolean> {
	const acl = await readMailboxAcl(env, mailboxId);
	if (acl === null) return true;
	if (isDev) return true;
	const email = callerEmailFromJwt(jwtToken);
	if (!email) return false;
	return callerInAcl(acl, email, callerGroupsFromJwt(jwtToken), isDev);
}
