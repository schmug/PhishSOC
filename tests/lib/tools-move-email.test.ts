// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi } from "vitest";
import { toolMoveEmail } from "../../workers/lib/tools";
import type { Env } from "../../workers/types";

function makeEnv(moveEmail: (id: string, folderId: string) => Promise<boolean>): Env {
	const stub = { moveEmail: vi.fn(moveEmail) };
	return { MAILBOX: { idFromName: () => "id", get: () => stub } } as unknown as Env;
}

describe("toolMoveEmail", () => {
	it("reports the move when the DO moved the email", async () => {
		const result = await toolMoveEmail(makeEnv(async () => true), "me@a.test", "e-1", "archive");
		expect(result).toEqual({ status: "moved", emailId: "e-1", folder: "archive" });
	});

	it("reports not found when the DO moved nothing", async () => {
		const result = await toolMoveEmail(makeEnv(async () => false), "me@a.test", "missing", "archive");
		expect(result).toEqual({ error: "Email or folder not found" });
	});
});
