// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Pluggable per-mailbox detector interface (issue #26).
 *
 * Each detector receives the incoming email's sender data and a narrow
 * stub for reading per-mailbox DO state. Detectors are expected to run
 * within the synchronous security pipeline and must not perform unbounded
 * work. Each detector's score contribution is capped at +30 by the caller
 * (mirrors the YARA async deep-scan cap).
 */

export interface DetectorInput {
	/** Sender email address, already lowercased. */
	senderAddress: string;
	/** Sender display name, already lowercased and trimmed. */
	senderName: string;
}

export interface SenderGraphRecord {
	sender_address: string;
	message_count: number;
}

export interface SenderGraphStub {
	getSenderGraphByName(senderName: string): Promise<SenderGraphRecord[]>;
}

export interface Detector {
	score(input: DetectorInput, stub: SenderGraphStub): Promise<{ score: number; reason?: string }>;
}

/**
 * BEC / display-name impersonation detector.
 *
 * Queries the per-mailbox sender graph for the email's display name. If
 * the name has prior history from one or more known addresses and the
 * current sender address is NOT among them, this is a candidate BEC
 * signal: someone is claiming a familiar identity from a new address.
 *
 * Score ramps with history depth (more prior messages = higher confidence
 * the known-name is real, so the impersonation is more suspicious):
 *   - 1 prior message    → +10 (low confidence — name may be common)
 *   - 2–4 prior messages → +15
 *   - ≥5 prior messages  → +25
 *
 * Returns 0 when:
 *   - The display name is absent or empty
 *   - No prior messages used this display name (no history to impersonate)
 *   - The current sender address is already in the known-address set
 */
export class SenderGraphDetector implements Detector {
	async score(
		input: DetectorInput,
		stub: SenderGraphStub,
	): Promise<{ score: number; reason?: string }> {
		const { senderName, senderAddress } = input;
		if (!senderName) return { score: 0 };

		const records = await stub.getSenderGraphByName(senderName);
		if (records.length === 0) return { score: 0 };

		const knownAddresses = new Set(records.map((r) => r.sender_address));
		if (knownAddresses.has(senderAddress)) return { score: 0 };

		const totalHistory = records.reduce((sum, r) => sum + r.message_count, 0);
		const score = totalHistory >= 5 ? 25 : totalHistory >= 2 ? 15 : 10;
		return {
			score,
			reason: `display name "${senderName}" previously seen from ${knownAddresses.size} known address(es), new sender (BEC signal)`,
		};
	}
}
