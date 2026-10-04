// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/** Route tests for POST /emails/:id/not-phish (issue #751). Synthetic data only. */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../workers/lib/mailbox", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox")>();
	return {
		...original,
		requireMailbox: createMiddleware(async (_c, next) => {
			await next();
		}),
	};
});

import { emailFeedbackRoutes } from "../../workers/routes/email-feedback";
import type { MailboxContext } from "../../workers/lib/mailbox";

function makeApp() {
	const labels = new Map<string, { label: string; created_at: string }>();
	const known = new Set(["e1"]);
	const stub = {
		async markNotPhish(id: string) {
			if (!known.has(id)) return null;
			if (!labels.has(id)) labels.set(id, { label: "not_phish", created_at: "2026-10-04T12:00:00.000Z" });
			return { email_id: id, ...labels.get(id)!, verdict_action: "tag", verdict_score: 40 };
		},
	};
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as never);
		await next();
	});
	app.route("/api/v1/mailboxes/:mailboxId/emails", emailFeedbackRoutes);
	return { app, labels };
}

const url = (id: string) => `/api/v1/mailboxes/box%40a.test/emails/${id}/not-phish`;

describe("POST /emails/:id/not-phish", () => {
	it("persists the label and returns it", async () => {
		const { app, labels } = makeApp();
		const res = await app.request(url("e1"), { method: "POST" });
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ feedback: { email_id: "e1", label: "not_phish", verdict_action: "tag", verdict_score: 40 } });
		expect(labels.size).toBe(1);
	});

	it("is idempotent across repeated clicks", async () => {
		const { app, labels } = makeApp();
		await app.request(url("e1"), { method: "POST" });
		const res = await app.request(url("e1"), { method: "POST" });
		expect(res.status).toBe(200);
		expect(labels.size).toBe(1);
	});

	it("404s for an unknown email", async () => {
		const { app, labels } = makeApp();
		const res = await app.request(url("missing"), { method: "POST" });
		expect(res.status).toBe(404);
		expect(labels.size).toBe(0);
	});
});
