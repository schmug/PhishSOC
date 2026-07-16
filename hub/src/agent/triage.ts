// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Queue consumer. For each new event, run the LLM to:
 *   - suggest MISP taxonomy tags
 *   - write a one-line summary stored as an event comment
 *
 * Dedup decisions and trust-weighting are handled by the aggregation step at
 * write time — the LLM is intentionally not allowed to change scores. Its
 * outputs are tags and human-readable text, nothing that affects promotion.
 */

import type { Env, TriageMessage } from "../types";

const TAG_PROMPT = `You are assigning MISP taxonomy tags to a threat intel event. Return a JSON array of up to 5 lowercase tag strings drawn from this allowlist:
["phishing", "bec", "malware-delivery", "credential-theft", "impersonation", "tlp:green", "tlp:amber", "type:osint", "campaign-unknown"]
No explanation, no other text — just the JSON array.`;

export async function consumeTriageBatch(
	batch: MessageBatch<TriageMessage>,
	env: Env,
): Promise<void> {
	for (const msg of batch.messages) {
		try {
			await triageEvent(env, msg.body.event_uuid);
			msg.ack();
		} catch (e) {
			console.error("triage failed:", (e as Error).message);
			msg.retry();
		}
	}
}

async function triageEvent(env: Env, uuid: string) {
	const event = await env.DB.prepare(
		`SELECT event_json FROM events WHERE uuid = ?1`,
	)
		.bind(uuid)
		.first<{ event_json: string }>();
	if (!event) return;
	const parsed = JSON.parse(event.event_json) as {
		Event: {
			info?: string;
			Attribute?: Array<{ type: string; value: string }>;
		};
	};
	const info = parsed.Event?.info ?? "";
	const attrs = parsed.Event?.Attribute ?? [];
	const summary = `info="${info}" attrs=${attrs
		.slice(0, 10)
		.map((a) => `${a.type}:${a.value}`)
		.join(",")}`;

	let tags: string[] = [];
	try {
		const response = (await env.AI.run(
			"@cf/meta/llama-3.1-8b-instruct-fast" as Parameters<Ai["run"]>[0],
			{
				messages: [
					{ role: "system", content: TAG_PROMPT },
					{ role: "user", content: summary.slice(0, 2000) },
				],
				max_tokens: 120,
				temperature: 0,
			},
		)) as { response?: string };
		const match = response?.response?.match(/\[[\s\S]*\]/);
		if (match) {
			const arr = JSON.parse(match[0]);
			if (Array.isArray(arr))
				tags = arr.filter((t) => typeof t === "string").slice(0, 5);
		}
	} catch (e) {
		console.error("tag generation failed:", (e as Error).message);
	}

	if (tags.length > 0) {
		// ⚡ Bolt: Batch D1 queries for tag insertions to eliminate N+1 latency
		// when an event is assigned multiple tags by the triage agent.
		const tagStatements: D1PreparedStatement[] = [];
		for (const t of tags) {
			tagStatements.push(
				env.DB.prepare(`INSERT OR IGNORE INTO tags (name) VALUES (?1)`).bind(t),
			);
			tagStatements.push(
				env.DB.prepare(
					`INSERT OR IGNORE INTO event_tags (event_uuid, tag_name) VALUES (?1, ?2)`,
				).bind(uuid, t),
			);
		}
		await env.DB.batch(tagStatements);
	}
}
