// Classifier evaluation harness. Runs labeled cases through LLM classifier
// variants via the Workers AI REST API, reusing the production
// `classifyEmail` / `scoreClassification` unchanged (prompt, sanitizer,
// timeout budget, Jev fallback, parser). See ./README.md.
//
// Build + run from the repo root:
//   npx esbuild scripts/classifier-eval/harness.ts --bundle --platform=node \
//     --format=esm --outfile=scripts/classifier-eval/data/harness.mjs
//   CF_ACCOUNT_ID=... CF_API_TOKEN=$(npx wrangler auth token | tail -1) \
//     node scripts/classifier-eval/data/harness.mjs llama8b jev
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyEmail, scoreClassification } from "../../workers/security/classification";

const HERE = dirname(fileURLToPath(import.meta.url));
// The bundle is written into data/, so resolve paths from the source dir.
const ROOT = HERE.endsWith("/data") ? dirname(HERE) : HERE;
const DATA = join(ROOT, "data");

const ACCOUNT = process.env.CF_ACCOUNT_ID;
const TOKEN = process.env.CF_API_TOKEN;
if (!ACCOUNT || !TOKEN) throw new Error("set CF_ACCOUNT_ID and CF_API_TOKEN (npx wrangler auth token)");
const CASES = process.env.CASES ?? join(DATA, "cases.jsonl");
const OUT = process.env.OUT ?? join(DATA, "results");
const CONCURRENCY = Number(process.env.CONCURRENCY ?? 2);
const BUDGET_USD = Number(process.env.BUDGET_USD ?? 2);

// $ per 1M tokens [input, output]. Workers AI pricing page, 2026-09-26.
const PRICES: Record<string, [number, number]> = {
	"@cf/meta/llama-3.1-8b-instruct-fast": [0.045, 0.384],
	"@cf/meta/llama-4-scout-17b-16e-instruct": [0.27, 0.85],
	"@cf/openai/gpt-oss-20b": [0.2, 0.3],
	"typesafe/jev": [0.042, 0],
	// Input-only pricing. Workers AI pricing page, 2026-10-04.
	"@cf/cloudflare/clef": [0.24, 0],
	"@cf/cloudflare/clef-flash": [0.09, 0],
};

const prompt = (f: string) => readFileSync(join(ROOT, "prompts", f), "utf8");
// systemPrompt replaces only the chat system message; everything else is prod.
const VARIANTS: Record<string, { model: string; systemPrompt?: () => string }> = {
	llama8b: { model: "@cf/meta/llama-3.1-8b-instruct-fast" },
	"llama8b-v2": { model: "@cf/meta/llama-3.1-8b-instruct-fast", systemPrompt: () => prompt("llama-v2-loose.txt") },
	"llama8b-v3": { model: "@cf/meta/llama-3.1-8b-instruct-fast", systemPrompt: () => prompt("llama-v3-strict.txt") },
	scout: { model: "@cf/meta/llama-4-scout-17b-16e-instruct" },
	"scout-v3": { model: "@cf/meta/llama-4-scout-17b-16e-instruct", systemPrompt: () => prompt("llama-v3-strict.txt") },
	gptoss20b: { model: "@cf/openai/gpt-oss-20b" },
	jev: { model: "typesafe/jev" },
	clef: { model: "@cf/cloudflare/clef" },
	"clef-flash": { model: "@cf/cloudflare/clef-flash" },
};

type Case = {
	id: string; set: string; truth: string; sender: string; subject: string; bodyHtml: string;
	auth: { spf: string; dkim: string; dmarc: string };
};
type Rec = { latency_ms?: number; in_tok?: number; out_tok?: number; usd?: number; err?: string; models: string[] };

let spent = 0;

async function rest(model: string, body: unknown): Promise<any> {
	// Third-party models (typesafe/*) take {model, input} on the unified endpoint.
	const thirdParty = !model.startsWith("@cf/");
	const url = thirdParty
		? `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/ai/run`
		: `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/ai/run/${model}`;
	for (let attempt = 0; ; attempt++) {
		const r = await fetch(url, {
			method: "POST",
			headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
			body: JSON.stringify(thirdParty ? { model, input: body } : body),
		});
		const j: any = await r.json().catch(() => ({ success: false, errors: [{ message: `http ${r.status}` }] }));
		if (r.status === 429 && attempt < 4) {
			await new Promise((s) => setTimeout(s, 2000 * (attempt + 1)));
			continue;
		}
		if (!j.success) throw new Error(`http ${r.status}: ${JSON.stringify(j.errors).slice(0, 200)}`);
		return j.result;
	}
}

/** Accumulates spend. Checked between cases, not inside classifyEmail, whose catch would swallow it. */
function charge(model: string, rec: Rec) {
	const [pi, po] = PRICES[model] ?? [0, 0];
	const usd = ((rec.in_tok ?? 0) * pi + (rec.out_tok ?? 0) * po) / 1e6;
	rec.usd = (rec.usd ?? 0) + usd;
	spent += usd;
}

/** REST-backed stand-in for the Workers AI binding, so classifyEmail runs unmodified. */
function makeAi(rec: Rec, systemPrompt?: string): Ai {
	return {
		run: async (model: string, inputs: any) => {
			const t0 = Date.now();
			const body = structuredClone(inputs);
			rec.models.push(model);
			if (systemPrompt && body.messages) body.messages[0].content = systemPrompt;
			if (model.startsWith("@cf/openai/gpt-oss")) {
				// Reasoning model: prod's 200-token cap leaves no room for the answer.
				body.max_tokens = 1500;
				body.reasoning = { effort: "low" };
			}
			try {
				const res = await rest(model, body);
				rec.latency_ms = Date.now() - t0;
				const usage = res.usage ?? res.result?.usage;
				rec.in_tok = usage?.prompt_tokens ?? usage?.input_tokens;
				rec.out_tok = usage?.completion_tokens ?? usage?.output_tokens;
				charge(model, rec);
				// OpenAI-shaped chat results (gpt-oss) → the `{response}` shape classifyEmail reads.
				if (res.response === undefined && res.choices) return { response: res.choices[0]?.message?.content ?? "" };
				return res;
			} catch (e) {
				rec.latency_ms = Date.now() - t0;
				rec.err = String(e);
				throw e;
			}
		},
	} as unknown as Ai;
}

async function pool<T>(items: T[], n: number, fn: (t: T) => Promise<void>) {
	let i = 0;
	await Promise.all(Array.from({ length: n }, async () => {
		while (i < items.length) await fn(items[i++]);
	}));
}

const names = process.argv.slice(2);
if (!names.length || names.some((n) => !VARIANTS[n])) {
	throw new Error(`usage: harness.mjs <variant...>; variants: ${Object.keys(VARIANTS).join(", ")}`);
}
const cases: Case[] = readFileSync(CASES, "utf8").trim().split("\n").map((l) => JSON.parse(l))
	.filter((c: Case) => c.truth !== "exclude");
mkdirSync(OUT, { recursive: true });

for (const name of names) {
	const { model, systemPrompt } = VARIANTS[name];
	const out = join(OUT, `${name}.jsonl`);
	if (existsSync(out) && !process.env.FORCE) {
		console.log(`skip ${name}: ${out} exists (FORCE=1 to overwrite)`);
		continue;
	}
	const lines: string[] = [];
	await pool(cases, CONCURRENCY, async (c) => {
		const rec: Rec = { models: [] };
		const r = await classifyEmail(makeAi(rec, systemPrompt?.()), c, { model, skipOnTimeout: true });
		if (spent > BUDGET_USD) throw new Error(`BUDGET_USD exceeded: $${spent.toFixed(3)} > $${BUDGET_USD}`);
		lines.push(JSON.stringify({
			id: c.id, set: c.set, truth: c.truth, label: r.label, conf: r.confidence,
			contrib: scoreClassification(r).score, reasoning: r.reasoning.slice(0, 160),
			fallback: rec.models.length > 1, ...rec,
		}));
	});
	writeFileSync(out, lines.join("\n") + "\n");
	console.log(`${name}: ${lines.length} cases → ${out} (running spend $${spent.toFixed(4)})`);
}
console.log(`total spend $${spent.toFixed(4)}`);
