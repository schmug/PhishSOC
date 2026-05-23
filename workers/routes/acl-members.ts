// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * ACL member management endpoints (#240). Mounted under
 * `/api/v1/mailboxes/:mailboxId/acl`.
 *
 * Only the mailbox owner (the email stored in `acl.owner`) may call these
 * write endpoints. A caller admitted by CF Access but not the owner receives
 * 403. The ACL blob is not a settings tier; `stripDefaultEqual` is not used.
 */

import { Hono } from "hono";
import { requireMailbox, type MailboxContext } from "../lib/mailbox";
import { readMailboxAcl, writeMailboxAcl } from "../lib/mailbox-acl";

export const aclMemberRoutes = new Hono<MailboxContext>();

aclMemberRoutes.use("*", requireMailbox);

/**
 * Read the ACL for a mailbox (#291). Owner-only — returns { owner, members }.
 * Non-owner admitted callers receive 403. Unscoped mailboxes (no ACL blob)
 * return 404 with { acl_status: "unscoped" } so the UI can prompt lock-down.
 */
aclMemberRoutes.get("/", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;

	const acl = await readMailboxAcl(c.env, mailboxId);
	if (!acl) {
		return c.json({ acl_status: "unscoped" }, 404);
	}
	if (callerEmail !== null && callerEmail !== acl.owner) {
		return c.json({ error: "Forbidden" }, 403);
	}
	return c.json({ owner: acl.owner, members: acl.members, groups: acl.groups ?? [] });
});

/**
 * Lock down an unscoped (pre-#27) mailbox by creating its first ACL with the
 * caller as owner (#241). Returns 201 on success, 409 if an ACL already exists,
 * 400 when CF Access email is absent (dev mode).
 */
aclMemberRoutes.post("/", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;

	if (!callerEmail) {
		return c.json({ error: "CF Access email required to lock down a mailbox" }, 400);
	}

	const existing = await readMailboxAcl(c.env, mailboxId);
	if (existing) {
		return c.json({ error: "Mailbox is already scoped" }, 409);
	}

	const acl = { owner: callerEmail, members: [callerEmail] };
	await writeMailboxAcl(c.env, mailboxId, acl);
	return c.json({ owner: acl.owner, members: acl.members }, 201);
});

/** Add a member to the mailbox ACL. Idempotent if the email is already present. */
aclMemberRoutes.post("/members", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;

	const acl = await readMailboxAcl(c.env, mailboxId);
	if (!acl || callerEmail !== acl.owner) {
		return c.json({ error: "Forbidden" }, 403);
	}

	const body = (await c.req.json().catch(() => ({}))) as { email?: unknown };
	const rawEmail = typeof body.email === "string" ? body.email.trim() : "";
	if (!rawEmail) return c.json({ error: "Email required" }, 400);

	const memberEmail = rawEmail.toLowerCase();
	if (acl.members.includes(memberEmail)) {
		return c.json({ owner: acl.owner, members: acl.members });
	}

	const updated = { owner: acl.owner, members: [...acl.members, memberEmail] };
	await writeMailboxAcl(c.env, mailboxId, updated);
	return c.json({ owner: updated.owner, members: updated.members });
});

/**
 * Transfer ACL ownership to an existing member (#293).
 * Only the current owner may call this. The target must already be in
 * `acl.members`; the old owner stays as a member after the transfer.
 */
aclMemberRoutes.post("/transfer", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;

	const acl = await readMailboxAcl(c.env, mailboxId);
	if (!acl || callerEmail !== acl.owner) {
		return c.json({ error: "Forbidden" }, 403);
	}

	const body = (await c.req.json().catch(() => ({}))) as { email?: unknown };
	const rawEmail = typeof body.email === "string" ? body.email.trim() : "";
	if (!rawEmail) return c.json({ error: "Email required" }, 400);

	const targetEmail = rawEmail.toLowerCase();
	if (!acl.members.includes(targetEmail)) {
		return c.json({ error: "Target must already be a member" }, 400);
	}

	const updated = { owner: targetEmail, members: acl.members };
	await writeMailboxAcl(c.env, mailboxId, updated);
	return c.json({ owner: updated.owner, members: updated.members });
});

/** Remove a member from the mailbox ACL. The owner cannot remove themselves. */
aclMemberRoutes.delete("/members/:memberEmail", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;
	const memberEmail = decodeURIComponent(c.req.param("memberEmail")!).toLowerCase();

	const acl = await readMailboxAcl(c.env, mailboxId);
	if (!acl || callerEmail !== acl.owner) {
		return c.json({ error: "Forbidden" }, 403);
	}

	if (memberEmail === acl.owner) {
		return c.json({ error: "Cannot remove the mailbox owner" }, 400);
	}

	const updated = {
		owner: acl.owner,
		members: acl.members.filter((m) => m !== memberEmail),
		groups: acl.groups,
	};
	await writeMailboxAcl(c.env, mailboxId, updated);
	return c.json({ owner: updated.owner, members: updated.members, groups: updated.groups ?? [] });
});

/**
 * Add a CF Access group name to the mailbox ACL (#295). Idempotent.
 * The group name must match the name shown in the Cloudflare Access dashboard.
 * Owner-only.
 */
aclMemberRoutes.post("/groups", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;

	const acl = await readMailboxAcl(c.env, mailboxId);
	if (!acl || callerEmail !== acl.owner) {
		return c.json({ error: "Forbidden" }, 403);
	}

	const body = (await c.req.json().catch(() => ({}))) as { group?: unknown };
	const rawGroup = typeof body.group === "string" ? body.group.trim() : "";
	if (!rawGroup) return c.json({ error: "Group name required" }, 400);

	const existingGroups = acl.groups ?? [];
	if (existingGroups.includes(rawGroup)) {
		return c.json({ owner: acl.owner, members: acl.members, groups: existingGroups });
	}

	const updated = { ...acl, groups: [...existingGroups, rawGroup] };
	await writeMailboxAcl(c.env, mailboxId, updated);
	return c.json({ owner: updated.owner, members: updated.members, groups: updated.groups });
});

/** Remove a CF Access group name from the mailbox ACL. Owner-only. */
aclMemberRoutes.delete("/groups/:groupName", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const callerEmail =
		c.req.header("cf-access-authenticated-user-email")?.toLowerCase() ?? null;
	const groupName = decodeURIComponent(c.req.param("groupName")!);

	const acl = await readMailboxAcl(c.env, mailboxId);
	if (!acl || callerEmail !== acl.owner) {
		return c.json({ error: "Forbidden" }, 403);
	}

	const updated = {
		...acl,
		groups: (acl.groups ?? []).filter((g) => g !== groupName),
	};
	await writeMailboxAcl(c.env, mailboxId, updated);
	return c.json({ owner: updated.owner, members: updated.members, groups: updated.groups ?? [] });
});
