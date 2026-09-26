// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { MailboxSettings } from "../../shared/mailbox-settings";
import { stripDefaultEqual } from "../../workers/lib/mailbox-settings";

describe("hideFromAllInboxes mailbox setting", () => {
	it("parses as an optional boolean", () => {
		expect(MailboxSettings.parse({ hideFromAllInboxes: true }).hideFromAllInboxes).toBe(true);
		expect(MailboxSettings.parse({}).hideFromAllInboxes).toBeUndefined();
		expect(MailboxSettings.safeParse({ hideFromAllInboxes: "yes" }).success).toBe(false);
	});

	it("strips the false default so absent-key semantics hold", () => {
		expect(stripDefaultEqual({ hideFromAllInboxes: false })).toEqual({});
	});

	it("keeps an explicit true", () => {
		expect(stripDefaultEqual({ hideFromAllInboxes: true })).toEqual({ hideFromAllInboxes: true });
	});
});
