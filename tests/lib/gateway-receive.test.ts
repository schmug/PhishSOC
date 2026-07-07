import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../workers/lib/gateway-relay", () => ({
	relayAfterVerdict: vi.fn(async () => "relayed"),
}));
vi.mock("../../workers/security", () => ({
	runSecurityPipeline: vi.fn(),
}));

import { relayAfterVerdict } from "../../workers/lib/gateway-relay";
import { runSecurityPipeline } from "../../workers/security";
import { receiveGatewayPassthrough } from "../../workers/lib/gateway-receive";
import { clearDomainSettingsCache } from "../../workers/lib/domain-settings";
import type { GatewayInbound } from "../../workers/providers/types";
import type { Env } from "../../workers/types";

function fakeEnv(domainSettings: Record<string, unknown>): Env {
	return {
		BUCKET: {
			get: async (key: string) =>
				key === "domains/example.com.json"
					? { etag: "e1", json: async () => domainSettings }
					: null,
		},
	} as unknown as Env;
}

const inbound: GatewayInbound = {
	kind: "gateway",
	rawEmail: new TextEncoder().encode("Subject: t\r\n\r\nbody\r\n").buffer as ArrayBuffer,
	parsedEmail: { subject: "t", from: { address: "s@o.test" }, headers: [] } as never,
	recipient: "ghost@example.com",
	domain: "example.com",
	envelopeFrom: "s@o.test",
};

const ctx = { waitUntil: () => {} } as unknown as ExecutionContext;

const relayEnabled = { relay: { enabled: true, target: { host: "smtp-relay.gmail.com" } } };

function pipelineVerdict(action: string) {
	vi.mocked(runSecurityPipeline).mockResolvedValueOnce({
		verdict: { action, score: 70, confidence: 0.9, explanation: "", auth: { spf: "fail", dkim: "fail", dmarc: "fail", dkimObservations: [] }, classification: {}, signals: [] },
		skipped: false,
		stageTrace: [],
	} as never);
}

describe("receiveGatewayPassthrough", () => {
	beforeEach(() => {
		clearDomainSettingsCache();
		vi.mocked(relayAfterVerdict).mockClear();
		vi.mocked(runSecurityPipeline).mockReset();
	});

	it("runs the pipeline stateless and relays with passthrough=true", async () => {
		pipelineVerdict("allow");
		await receiveGatewayPassthrough(inbound, fakeEnv(relayEnabled), ctx);
		expect(runSecurityPipeline).toHaveBeenCalledWith(
			expect.objectContaining({ stateless: true, mailboxId: "ghost@example.com" }),
		);
		expect(relayAfterVerdict).toHaveBeenCalledWith(
			expect.objectContaining({
				passthrough: true,
				rcptTo: "ghost@example.com",
				envelopeFrom: "s@o.test",
				verdict: expect.objectContaining({ action: "allow" }),
			}),
		);
	});

	it("caps quarantine and block verdicts at tag before relaying", async () => {
		pipelineVerdict("quarantine");
		await receiveGatewayPassthrough(inbound, fakeEnv(relayEnabled), ctx);
		expect(relayAfterVerdict).toHaveBeenCalledWith(
			expect.objectContaining({ verdict: expect.objectContaining({ action: "tag" }) }),
		);
	});

	it("pipeline failure relays unscanned (verdict null) rather than eating mail", async () => {
		vi.mocked(runSecurityPipeline).mockRejectedValueOnce(new Error("boom"));
		await receiveGatewayPassthrough(inbound, fakeEnv(relayEnabled), ctx);
		expect(relayAfterVerdict).toHaveBeenCalledWith(expect.objectContaining({ verdict: null }));
	});

	it("drops silently when the relay policy has vanished", async () => {
		await receiveGatewayPassthrough(inbound, fakeEnv({}), ctx);
		expect(relayAfterVerdict).not.toHaveBeenCalled();
	});
});
