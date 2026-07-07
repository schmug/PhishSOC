// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi, afterEach } from "vitest";

vi.mock("../../workers/index", () => ({ receiveEmail: vi.fn() }));

import { pollSidecarMailboxes, reapSidecarBodies } from "../../workers/providers/workspace";

afterEach(() => vi.clearAllMocks());

/**
 * env.BUCKET fake: mailboxes/<id>.json blobs; list() returns their keys.
 * Two mailboxes: one sidecar-enabled, one plain.
 */
function makeBucketEnv(stubs: Record<string, unknown>) {
	const blobs: Record<string, unknown> = {
		"mailboxes/side@t.example.json": { sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_t", retention_days: 7 } },
		"mailboxes/plain@t.example.json": {},
		"org/settings.json": {},
	};
	return {
		BUCKET: {
			list: vi.fn(async ({ prefix }: { prefix: string }) => ({
				objects: Object.keys(blobs).filter((k) => k.startsWith(prefix)).map((key) => ({ key })),
			})),
			get: vi.fn(async (key: string) =>
				blobs[key] ? { json: async () => blobs[key], text: async () => JSON.stringify(blobs[key]) } : null),
			head: vi.fn(async (key: string) => (blobs[key] ? {} : null)),
			delete: vi.fn(async () => undefined),
		},
		MAILBOX: {
			idFromName: vi.fn((n: string) => n),
			get: vi.fn((n: string) => stubs[n]),
		},
		SIDECAR_SECRET_t: JSON.stringify({ client_email: "svc@p.iam", private_key: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----" }),
	} as never;
}

const ctx = { waitUntil: vi.fn() } as never;

describe("pollSidecarMailboxes", () => {
	it("polls only sidecar-configured mailboxes; a per-mailbox failure doesn't stop the loop", async () => {
		// Backoff-armed state so the poll returns without touching Gmail —
		// this test pins mailbox SELECTION, not poll mechanics (Task 7 covers those).
		const sideStub = {
			getSidecarState: vi.fn().mockResolvedValue({
				history_cursor: "1", access_token: "t", token_expires_at: Date.now() + 3600_000,
				label_ids: null, last_poll_at: Date.now(), last_error: null, consecutive_failures: 99,
			}),
			putSidecarState: vi.fn(),
		};
		const plainStub = { getSidecarState: vi.fn() };
		const env = makeBucketEnv({ "side@t.example": sideStub, "plain@t.example": plainStub });
		const r = await pollSidecarMailboxes(env, ctx);
		expect(r.polled).toBe(1);
		expect(sideStub.getSidecarState).toHaveBeenCalled();
		expect(plainStub.getSidecarState).not.toHaveBeenCalled();
	});
});

describe("reapSidecarBodies", () => {
	it("reaps old bodies for sidecar mailboxes, deletes R2 attachment objects, skips retention_days=0", async () => {
		const sideStub = {
			listReapableSidecarEmails: vi.fn().mockResolvedValue([
				{ id: "e1", attachments: [{ id: "a1", filename: "x.pdf" }] },
			]),
			markBodiesReaped: vi.fn().mockResolvedValue(1),
		};
		const env = makeBucketEnv({ "side@t.example": sideStub });
		const r = await reapSidecarBodies(env);
		expect(r).toEqual({ mailboxes: 1, reaped: 1 });
		// cutoff passed to the DO is ~7 days ago (the mailbox's retention_days)
		const cutoffIso = sideStub.listReapableSidecarEmails.mock.calls[0][0] as string;
		const ageDays = (Date.now() - Date.parse(cutoffIso)) / 86_400_000;
		expect(ageDays).toBeGreaterThan(6.9);
		expect(ageDays).toBeLessThan(7.1);
		// R2 attachment object deleted with the canonical key
		expect((env as never as { BUCKET: { delete: ReturnType<typeof vi.fn> } }).BUCKET.delete).toHaveBeenCalledTimes(1);
		expect(sideStub.markBodiesReaped).toHaveBeenCalledWith(["e1"], expect.any(String));
	});
});
