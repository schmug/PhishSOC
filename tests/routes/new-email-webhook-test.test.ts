// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * `POST /api/v1/new-email-webhook/test` — the "Send test" button's endpoint.
 *
 * Every failure path in `dispatchNewEmailNotification` is deliberately silent
 * (see that module's fire-and-forget contract), so an operator who typos a
 * secret name, writes a malformed `{url, headers}` envelope, or whose receiver
 * rejects the HMAC has no way to find out short of waiting for real mail and
 * reading Worker logs. This endpoint is the inverse: awaited, and it reports
 * exactly which stage failed.
 *
 * Staged `{ ok, stage, error }` shape mirrors `workers/routes/sidecar.ts`.
 *
 * Two invariants this suite pins:
 *   - The destination is resolved server-side from a `NEW_EMAIL_WEBHOOK_`
 *     secret, never from the request, so the endpoint can't become a generic
 *     outbound-fetch primitive.
 *   - No response ever carries a secret's value or a computed signature.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { app } from "../../workers/index";

const SECRET_NAME = "NEW_EMAIL_WEBHOOK_SOC";
const WEBHOOK_URL = "https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t";

function post(body: unknown, env: Record<string, unknown>) {
	return app.request(
		"/api/v1/new-email-webhook/test",
		{
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		},
		env,
	);
}

describe("POST /api/v1/new-email-webhook/test — delivery", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response(null, { status: 200 }));
	});
	afterEach(() => vi.restoreAllMocks());

	it("posts to the secret's URL and reports ok on a 2xx", async () => {
		const res = await post(
			{ urlSecret: SECRET_NAME },
			{ [SECRET_NAME]: WEBHOOK_URL },
		);

		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true, status: 200 });

		expect(fetchSpy).toHaveBeenCalledTimes(1);
		const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		expect(url).toBe(WEBHOOK_URL);
		expect(init.method).toBe("POST");
	});
});

describe("POST /api/v1/new-email-webhook/test — stages", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response(null, { status: 200 }));
	});
	afterEach(() => vi.restoreAllMocks());

	it("reports the config stage when no secret name is submitted", async () => {
		const res = await post({}, {});

		expect(await res.json()).toMatchObject({ ok: false, stage: "config" });
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("reports the config stage for a name outside the NEW_EMAIL_WEBHOOK_ prefix", async () => {
		// The prefix guard is what stops a settings write naming an unrelated
		// secret and having its value POSTed to an operator-chosen endpoint.
		// A wrong prefix is an operator typo, not an environment problem.
		const res = await post(
			{ urlSecret: "CONFIRMATION_TOKEN_SECRET" },
			{ CONFIRMATION_TOKEN_SECRET: "s3cr3t-token-value" },
		);

		expect(await res.json()).toMatchObject({ ok: false, stage: "config" });
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("reports the secret stage when the named secret is not set in the environment", async () => {
		const res = await post({ urlSecret: "NEW_EMAIL_WEBHOOK_ABSENT" }, {});

		const body = (await res.json()) as { ok: boolean; stage: string; error: string };
		expect(body).toMatchObject({ ok: false, stage: "secret" });
		expect(body.error).toContain("NEW_EMAIL_WEBHOOK_ABSENT");
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("reports the secret stage for an envelope with no usable url", async () => {
		const res = await post(
			{ urlSecret: SECRET_NAME },
			{ [SECRET_NAME]: JSON.stringify({ headers: { Authorization: "Bearer tok" } }) },
		);

		expect(await res.json()).toMatchObject({ ok: false, stage: "secret" });
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("reports the delivery stage and the status code on a non-2xx", async () => {
		fetchSpy.mockResolvedValue(new Response("nope", { status: 403 }));

		const res = await post({ urlSecret: SECRET_NAME }, { [SECRET_NAME]: WEBHOOK_URL });

		expect(await res.json()).toMatchObject({ ok: false, stage: "delivery", status: 403 });
	});

	it("reports the delivery stage when the request never completes", async () => {
		fetchSpy.mockRejectedValue(new Error("The operation was aborted due to timeout"));

		const res = await post({ urlSecret: SECRET_NAME }, { [SECRET_NAME]: WEBHOOK_URL });

		const body = (await res.json()) as { ok: boolean; stage: string; error: string };
		expect(body).toMatchObject({ ok: false, stage: "delivery" });
		expect(body.error).toContain("timeout");
	});
});

describe("POST /api/v1/new-email-webhook/test — fidelity with the real dispatch", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockResolvedValue(new Response(null, { status: 200 }));
	});
	afterEach(() => vi.restoreAllMocks());

	function sentBody(): string {
		return (fetchSpy.mock.calls[0][1] as RequestInit).body as string;
	}
	function sentHeaders(): Record<string, string> {
		return (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
	}

	it("signs the test exactly like real mail, so the receiver's HMAC check is exercised", async () => {
		await post(
			{ urlSecret: SECRET_NAME },
			{ [SECRET_NAME]: WEBHOOK_URL, NEW_EMAIL_WEBHOOK_SIGNING_SECRET: "whsec_test" },
		);

		expect(sentHeaders()["x-phishsoc-signature"]).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
	});

	it("sends the chat shape by default", async () => {
		await post({ urlSecret: SECRET_NAME }, { [SECRET_NAME]: WEBHOOK_URL });

		expect(Object.keys(JSON.parse(sentBody()))).toEqual(["text"]);
	});

	it("sends the structured shape when the draft selects the json format", async () => {
		await post({ urlSecret: SECRET_NAME, format: "json" }, { [SECRET_NAME]: WEBHOOK_URL });

		const payload = JSON.parse(sentBody()) as Record<string, unknown>;
		expect(payload).toHaveProperty("sender");
		expect(payload).toHaveProperty("verdictAction");
		expect(payload).not.toHaveProperty("text");
	});

	it("sends an unmistakably synthetic payload, so a consumer can tell it from mail", async () => {
		await post({ urlSecret: SECRET_NAME, format: "json" }, { [SECRET_NAME]: WEBHOOK_URL });

		const payload = JSON.parse(sentBody()) as { subject: string; messageId: string };
		expect(payload.subject).toMatch(/test/i);
		expect(payload.messageId).toBe("webhook-test");
	});

	it("labels the message with the tier it was sent from", async () => {
		// A shared channel receives tests from all three tiers; the operator
		// needs to see which config produced the one they are looking at.
		await post({ urlSecret: SECRET_NAME, tier: "org" }, { [SECRET_NAME]: WEBHOOK_URL });

		expect(JSON.parse(sentBody()).text).toContain("org");
	});
});

describe("POST /api/v1/new-email-webhook/test — never leaks the credential", () => {
	afterEach(() => vi.restoreAllMocks());

	it("keeps the resolved URL out of a transport error", async () => {
		// Some runtimes embed the request URL in the failure message. The
		// webhook URL is itself a bearer credential (a Google Chat hook carries
		// its key and token in the query string), so it must never reach a
		// response body.
		vi.spyOn(globalThis, "fetch").mockRejectedValue(
			new Error(`request to ${WEBHOOK_URL} failed, reason: ECONNREFUSED`),
		);

		const res = await post({ urlSecret: SECRET_NAME }, { [SECRET_NAME]: WEBHOOK_URL });

		const text = await res.text();
		expect(text).not.toContain("token=t");
		expect(text).not.toContain(WEBHOOK_URL);
		expect(text).toContain("ECONNREFUSED");
	});

	it("keeps an envelope's header credential out of the response", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
		const res = await post(
			{ urlSecret: SECRET_NAME },
			{ [SECRET_NAME]: JSON.stringify({ headers: { Authorization: "Bearer crsr_secret" } }) },
		);

		expect(await res.text()).not.toContain("crsr_secret");
	});
});
