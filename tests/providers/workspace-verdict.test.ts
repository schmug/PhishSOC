// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	SIDECAR_LABEL_NAMES,
	verdictLabelName,
	applyVerdictLabels,
	WorkspaceProvider,
} from "../../workers/providers/workspace";

describe("verdictLabelName", () => {
	it("maps every action to exactly one label", () => {
		expect(verdictLabelName("block")).toBe("PhishPilot/Quarantine");
		expect(verdictLabelName("quarantine")).toBe("PhishPilot/Quarantine");
		expect(verdictLabelName("tag")).toBe("PhishPilot/Suspicious");
		expect(verdictLabelName("allow")).toBe("PhishPilot/Allow");
	});
	it("treats an unknown action as allow (fail-open on labeling, never on scoring)", () => {
		expect(verdictLabelName("weird-future-action")).toBe("PhishPilot/Allow");
	});
});

describe("applyVerdictLabels", () => {
	afterEach(() => vi.unstubAllGlobals());
	const LABEL_IDS = { "PhishPilot/Quarantine": "LQ", "PhishPilot/Suspicious": "LS", "PhishPilot/Allow": "LA" };

	function captureModify() {
		const calls: Array<{ path: string; body: { addLabelIds: string[]; removeLabelIds: string[] } }> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => {
			const u = new URL(String(url));
			if (u.hostname !== "gmail.googleapis.com") throw new Error(`unexpected host ${u.hostname}`);
			calls.push({ path: u.pathname, body: JSON.parse(String(init?.body)) });
			return new Response("{}", { status: 200 });
		}));
		return calls;
	}

	it("label-only quarantine adds the quarantine label and removes nothing", async () => {
		const calls = captureModify();
		const applied = await applyVerdictLabels("tok", "g1", "quarantine", "label-only", LABEL_IDS);
		expect(applied).toEqual(["PhishPilot/Quarantine"]);
		expect(calls[0].body).toEqual({ addLabelIds: ["LQ"], removeLabelIds: [] });
	});

	it("label-and-archive quarantine also removes INBOX", async () => {
		const calls = captureModify();
		await applyVerdictLabels("tok", "g1", "block", "label-and-archive", LABEL_IDS);
		expect(calls[0].body).toEqual({ addLabelIds: ["LQ"], removeLabelIds: ["INBOX"] });
	});

	it("allow and tag never archive, regardless of quarantine_behavior", async () => {
		const calls = captureModify();
		await applyVerdictLabels("tok", "g1", "tag", "label-and-archive", LABEL_IDS);
		expect(calls[0].body).toEqual({ addLabelIds: ["LS"], removeLabelIds: [] });
	});
});

describe("WorkspaceProvider", () => {
	afterEach(() => vi.unstubAllGlobals());

	it("has id workspace-api and send() rejects (read-only sidecar)", async () => {
		const p = new WorkspaceProvider();
		expect(p.id).toBe("workspace-api");
		await expect(p.send({} as never, {} as never)).rejects.toThrow(/read-only|unsupported/i);
	});

	it("applyVerdict is a no-op in observe mode — resolves without any fetch/token work", async () => {
		// A fetch mock that THROWS on any call: if applyVerdict touches the
		// network (token mint, label list, modify) the test fails hard.
		vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("applyVerdict must not fetch in observe mode"); }));
		const env = {
			// Mode absent → observe (the default). Settings resolve to a valid
			// sidecar block but never active.
			BUCKET: {
				get: vi.fn(async () => ({
					async json() { return { sidecar: { provider: "workspace", credentials_secret_name: "SIDECAR_SECRET_x" } }; },
				})),
			},
			// Secret present so the ONLY thing keeping applyVerdict from fetching
			// is the mode gate, not a missing credential.
			SIDECAR_SECRET_x: JSON.stringify({
				client_email: "svc@p.iam.gserviceaccount.com",
				private_key: "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----",
			}),
		} as never;
		const p = new WorkspaceProvider();
		await expect(
			p.applyVerdict(env, { kind: "mailbox", mailboxId: "u@t.example", providerMessageId: "g1" } as never, { action: "quarantine" }),
		).resolves.toBeUndefined();
	});
});
