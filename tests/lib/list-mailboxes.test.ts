// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it, vi } from "vitest";
import { listMailboxes } from "../../workers/lib/email-helpers";

describe("listMailboxes", () => {
	it("follows the R2 list cursor across pages", async () => {
		const list = vi.fn(async (opts: { prefix: string; cursor?: string }) => {
			if (!opts.cursor) {
				return { objects: [{ key: "mailboxes/a@x.test.json" }], truncated: true, cursor: "page-2" };
			}
			expect(opts.cursor).toBe("page-2");
			return { objects: [{ key: "mailboxes/b@x.test.json" }], truncated: false };
		});
		const result = await listMailboxes({ list } as unknown as R2Bucket);
		expect(result).toEqual([
			{ id: "a@x.test", email: "a@x.test" },
			{ id: "b@x.test", email: "b@x.test" },
		]);
		expect(list).toHaveBeenCalledTimes(2);
		for (const [opts] of list.mock.calls) expect(opts.prefix).toBe("mailboxes/");
	});
});
