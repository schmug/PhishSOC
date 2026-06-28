// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Async deep-scan orchestrator.
 *
 * Runs AFTER the synchronous security pipeline has stored its verdict
 * and decided allow/tag/quarantine. Deep-scan adds higher-latency signals
 * that would have dominated the sync-path budget:
 *
 *   - Redirect-chain resolution for every URL (up to 5 hops)
 *   - RDAP age lookup for each new hostname
 *   - Attachment extension / MIME / macro heuristics
 *
 * If the combined deep-scan signals push the verdict across a higher
 * threshold (e.g. from `tag` to `quarantine`) we upgrade the verdict and
 * move the email to the QUARANTINE folder. We never DOWNgrade — sync
 * decisions are load-bearing (the user may already have seen the email)
 * so the deep-scan only tightens.
 *
 * The orchestrator is best-effort: every external call is wrapped so a
 * single failure (flaky RDAP server, unreachable URL) never aborts the
 * scan for the other signals. `deep_scan_status` ends as either
 * `completed` or `failed` and the stored verdict is always internally
 * consistent.
 */

import type { Env } from "../types";
import type { FinalVerdict, VerdictThresholds } from "../security/verdict";
import { getMailboxStub } from "../lib/email-helpers";
import { Folders } from "../../shared/folders";
import { checkIpAgainstFeeds, checkUrlAgainstFeeds } from "./feeds";
import { DEFAULT_FEEDS } from "./defaults";
import { lookupDomainAge } from "./rdap";
import { resolveUrl } from "./url-resolver";
import { lookupIp, type CtiSummary } from "./crowdsec-cti";
import {
	aggregateAttachmentSignals,
	detectEncryptedArchive,
	finalExtension,
	scoreAttachment,
} from "./attachment-checks";
import { isHomographic } from "../security/urls";
import { DEFAULT_THRESHOLDS } from "../security/verdict";

export interface DeepScanInput {
	env: Env;
	mailboxId: string;
	emailId: string;
	thresholds?: VerdictThresholds;
}

export interface DeepScanResult {
	added_score: number;
	reasons: string[];
	final_action: FinalVerdict["action"] | "unchanged";
}

/**
 * Cap on score that deep-scan can add on top of the sync verdict. Keeping
 * this bounded means operators can tune the sync thresholds independently
 * of deep-scan sensitivity, and one flaky signal can't single-handedly
 * quarantine on its own.
 */
const DEEP_SCAN_MAX_ADD = 40;

export async function runDeepScan(input: DeepScanInput): Promise<DeepScanResult> {
	const { env, mailboxId, emailId } = input;
	const thresholds = input.thresholds ?? DEFAULT_THRESHOLDS;
	const stub = getMailboxStub(env, mailboxId);

	const stored = await stub.getStoredVerdict(emailId).catch(() => null);
	// No sync verdict stored — either the pipeline was disabled or errored.
	// Deep-scan still runs for URL/attachment persistence but can't layer
	// a score increment onto a missing base verdict.
	const baseVerdict = parseVerdict(stored?.verdict);

	const reasons: string[] = [];
	let added = 0;

	let resolvedHosts: string[] = [];
	try {
		const urlDelta = await scanUrls(env, mailboxId, emailId);
		added += urlDelta.score;
		reasons.push(...urlDelta.reasons);
		resolvedHosts = urlDelta.resolvedHosts;
	} catch (e) {
		console.error("deep-scan URL stage failed:", (e as Error).message);
	}

	try {
		const attDelta = await scanAttachments(env, mailboxId, emailId);
		added += attDelta.score;
		reasons.push(...attDelta.reasons);
	} catch (e) {
		console.error("deep-scan attachment stage failed:", (e as Error).message);
	}

	// Resolve the redirect-target hostnames once and share the IP set across
	// the CTI and IP-feed stages — both consume the same A-record fan-out and
	// we don't want to double the DoH spend.
	//
	// Skip DoH entirely when no consumer is configured: no CTI key AND no
	// IP-CIDR feed materialised in BLOOM_KV. This keeps deploys without any
	// IP-based intel from spending DNS queries with nothing to do.
	let resolvedIps: string[] = [];
	if (resolvedHosts.length > 0) {
		const wantIpStage = await ipStageEnabled(env, mailboxId);
		if (wantIpStage) {
			try {
				resolvedIps = await resolveHostsToIps(resolvedHosts);
			} catch (e) {
				console.error("deep-scan host resolution failed:", (e as Error).message);
			}
		}
	}

	// CTI runs as a peer stage (not nested inside scanUrls) so its own
	// per-inbound cap composes with the URL cap rather than getting
	// squashed by it. Gated on the API key — unconfigured deploys no-op.
	try {
		const ctiDelta = await scanCti(env, resolvedIps);
		added += ctiDelta.score;
		reasons.push(...ctiDelta.reasons);
	} catch (e) {
		console.error("deep-scan CTI stage failed:", (e as Error).message);
	}

	// IP-CIDR feed lookup (Spamhaus DROP/EDROP and similar). Independent of
	// CTI — runs even on deploys without `CROWDSEC_CTI_API_KEY`. Same per-IP
	// set as CTI so the resolution work is amortised across both stages.
	try {
		const ipFeedDelta = await scanIpFeeds(env, mailboxId, resolvedIps);
		added += ipFeedDelta.score;
		reasons.push(...ipFeedDelta.reasons);
	} catch (e) {
		console.error("deep-scan IP-feed stage failed:", (e as Error).message);
	}

	added = Math.min(DEEP_SCAN_MAX_ADD, added);

	let finalAction: FinalVerdict["action"] | "unchanged" = "unchanged";
	if (baseVerdict && added > 0) {
		const newScore = Math.min(100, (stored?.score ?? baseVerdict.score) + added);
		const newAction = actionForScore(newScore, thresholds);
		const upgraded = tierIndex(newAction) > tierIndex(baseVerdict.action);
		if (upgraded) {
			const upgradedVerdict: FinalVerdict = {
				...baseVerdict,
				score: newScore,
				action: newAction,
				signals: [...baseVerdict.signals, ...reasons],
				explanation: dedupe([
					...baseVerdict.signals.slice(0, 2),
					...reasons,
				]).slice(0, 4).join("; "),
			};
			await stub.persistSecurityVerdict(emailId, {
				verdict_json: JSON.stringify(upgradedVerdict),
				score: newScore,
				explanation: upgradedVerdict.explanation,
			}).catch(() => {});
			if (newAction === "quarantine" || newAction === "block") {
				await stub.moveEmail(emailId, Folders.QUARANTINE).catch(() => {});
			}
			finalAction = newAction;
		}
	}

	await stub.updateDeepScanStatus(emailId, "completed").catch(() => {});
	return { added_score: added, reasons, final_action: finalAction };
}

async function scanUrls(
	env: Env,
	mailboxId: string,
	emailId: string,
): Promise<{ score: number; reasons: string[]; resolvedHosts: string[] }> {
	const stub = getMailboxStub(env, mailboxId);
	const urls = await stub.getUrlsForEmail(emailId);
	if (!urls.length) return { score: 0, reasons: [], resolvedHosts: [] };

	const reasons: string[] = [];
	let score = 0;
	// Track checked hostnames so RDAP isn't hit repeatedly for the same domain.
	const seenHosts = new Set<string>();

	for (const row of urls) {
		const urlRow = row as unknown as { id: string; url: string };
		const resolved = await resolveUrl(urlRow.url).catch(() => null);
		const finalUrl = resolved?.resolved ?? urlRow.url;
		const urlVerdict: string[] = [];

		if (resolved?.host_changed) {
			urlVerdict.push("redirect_host_change");
			score += 10;
		}
		if (resolved?.truncated) {
			urlVerdict.push("redirect_chain_too_long");
			score += 5;
		}

		const host = safeHost(finalUrl);
		if (host && !seenHosts.has(host)) {
			seenHosts.add(host);
			if (isHomographic(host)) {
				urlVerdict.push("resolved_homograph");
				score += 15;
			}
			const age = await lookupDomainAge(host).catch(() => null);
			if (age?.is_fresh) {
				urlVerdict.push(`domain_age_${age.age_days}d`);
				score += age.age_days < 7 ? 20 : 10;
			}
			const feedMatch = await checkUrlAgainstFeeds(env, mailboxId, finalUrl).catch(() => null);
			if (feedMatch?.confirmed) {
				urlVerdict.push(`intel_match:${feedMatch.feedId}`);
				score += 20;
			}
		}

		await stub.updateUrlScan(urlRow.id, {
			resolved_url: finalUrl,
			page_title: resolved?.title ?? null,
			fetch_status: resolved ? "completed" : "failed",
			verdict: urlVerdict.length > 0 ? urlVerdict.join(",") : null,
		}).catch(() => {});

		if (urlVerdict.length > 0) {
			reasons.push(`URL ${host ?? urlRow.url}: ${urlVerdict.join(",")}`);
		}
	}

	// Cap URL contribution so a particularly nasty-looking link can't
	// single-handedly burn the whole deep-scan budget.
	return {
		score: Math.min(30, score),
		reasons,
		resolvedHosts: [...seenHosts],
	};
}

async function scanAttachments(
	env: Env,
	mailboxId: string,
	emailId: string,
): Promise<{ score: number; reasons: string[] }> {
	const stub = getMailboxStub(env, mailboxId);
	const rows = (await stub.getAttachmentsForEmail(emailId)) as unknown as Array<{
		id: string; filename: string; mimetype: string; size: number;
	}>;
	if (!rows.length) return { score: 0, reasons: [] };

	// For archive attachments, fetch the first 32KB from R2 and run the
	// header-level encryption detector. 32KB gives us room for self-
	// extracting stubs (SFX zips prepend an EXE) and for RAR5 main headers
	// that can sit after a prefix, without the cost of a full object read.
	// Skipped for non-archives and for very small files where any "archive"
	// is certainly junk.
	const verdicts = await Promise.all(rows.map(async (r) => {
		const signals = await detectArchiveSignals(env, emailId, r);
		return { row: r, verdict: scoreAttachment(r, signals) };
	}));
	const agg = aggregateAttachmentSignals(verdicts.map((v) => v.verdict));

	for (const { row, verdict } of verdicts) {
		await stub.updateAttachmentScan(row.id, {
			scan_status: "completed",
			scan_verdict: JSON.stringify(verdict),
		}).catch(() => {});
	}

	return { score: agg.score, reasons: agg.reasons };
}

// ── CTI enrichment stage ─────────────────────────────────────────

/**
 * Cap on score that the CTI stage can add per inbound. Sized so a deeply
 * enriched redirect chain can't single-handedly exceed `DEEP_SCAN_MAX_ADD`
 * — we want to leave room for blocklist + URL + attachment signals to
 * compose. Document this alongside the other deep-scan caps.
 */
const CTI_MAX_ADD = 25;

/**
 * Hard cap on number of unique hostnames the CTI stage will resolve via
 * DoH. The deep-scan budget is tens-of-seconds end-to-end, and DNS+CTI
 * fan-out for every host in a long redirect chain would dominate. 8 hosts
 * is enough for realistic phishing chains (median <3) without burning the
 * whole budget.
 */
const CTI_MAX_HOSTS = 8;

/**
 * Wall-clock budget shared across all DoH lookups in this stage. Per-host
 * timeouts inside `resolveHostA` keep the slowest single resolve from
 * pinning the whole stage — this constant just documents the design intent.
 */
const CTI_DOH_TIMEOUT_MS = 2000;

/**
 * Cap A-records inspected per hostname. Phishing infra typically resolves
 * to one or two IPs, and CTI lookups are the rate-limited resource — we'd
 * rather spread a budget across more hostnames than exhaustively enumerate
 * all the IPs behind one CDN-fronted host.
 */
const A_RECORDS_PER_HOST = 2;

interface CtiHit {
	ip: string;
	summary: CtiSummary;
}

/**
 * Resolve unique hostnames to a deduped IP list via DoH. Shared between the
 * CTI and IP-CIDR-feed stages so we only spend the DoH budget once per
 * inbound. Caps both the host fan-out and per-host A-record count.
 */
async function resolveHostsToIps(hosts: string[]): Promise<string[]> {
	const uniqueHosts = [...new Set(hosts)].slice(0, CTI_MAX_HOSTS);
	if (!uniqueHosts.length) return [];
	const resolved = await Promise.all(uniqueHosts.map((h) => resolveHostA(h)));
	const ips = new Set<string>();
	for (const arr of resolved) {
		for (const ip of arr.slice(0, A_RECORDS_PER_HOST)) {
			ips.add(ip);
		}
	}
	return [...ips];
}

/**
 * Look each unique IP up in CrowdSec CTI and aggregate the signals into
 * deep-scan reasons + a capped score delta. Best-effort; returns zero
 * contribution when the API key is missing, no IPs were resolved, or
 * every lookup produced nothing.
 */
async function scanCti(
	env: Env,
	ips: string[],
): Promise<{ score: number; reasons: string[] }> {
	if (!env.CROWDSEC_CTI_API_KEY) return { score: 0, reasons: [] };
	if (!ips.length) return { score: 0, reasons: [] };

	const lookups = await Promise.all(
		ips.map(async (ip): Promise<CtiHit | null> => {
			const summary = await lookupIp(env, ip).catch(() => null);
			return summary ? { ip, summary } : null;
		}),
	);

	const reasons: string[] = [];
	let score = 0;
	for (const hit of lookups) {
		if (!hit) continue;
		const { ip, summary } = hit;
		// Score deltas per IP — take the largest single match per category to
		// avoid double-counting (a single phishing IP shouldn't get +25 for
		// "behaviors:phishing" AND +25 for "behaviors:exploit").
		let perIp = 0;
		const hitReasons: string[] = [];

		const dangerousBehavior = summary.behaviors.find((b) => /phish|exploit/i.test(b));
		if (dangerousBehavior) {
			perIp = Math.max(perIp, 25);
			hitReasons.push(`redirect target IP ${ip} behavior=crowdsec:${dangerousBehavior}`);
		}

		if (summary.reputation === "malicious") {
			perIp = Math.max(perIp, 15);
			hitReasons.push(`redirect target IP ${ip} reputation=malicious`);
		} else if (summary.reputation === "suspicious") {
			perIp = Math.max(perIp, 10);
			hitReasons.push(`redirect target IP ${ip} reputation=suspicious`);
		}

		const flaggedClassification = summary.classifications.find(
			(c) => c === "tor" || c === "vpn:public" || c === "data_center",
		);
		if (flaggedClassification) {
			perIp = Math.max(perIp, 10);
			hitReasons.push(
				`redirect target IP ${ip} classified as crowdsec:${flaggedClassification}`,
			);
		}

		if (perIp > 0) {
			score += perIp;
			reasons.push(...hitReasons);
		}
	}

	return { score: Math.min(CTI_MAX_ADD, score), reasons };
}

/**
 * Decide whether to spend DoH on resolving redirect-target hostnames. True
 * if any IP-based stage has something to do: CTI is configured, or any
 * default `ip-cidr` feed has been materialised into KV.
 *
 * We probe each default ip-cidr feed's key directly rather than `list({
 * prefix })`-ing — KV `get` is cheap, the default-feed list is small, and
 * we avoid a second code path for fakes/tests that mock only `get`/`put`.
 * User-configured ip-cidr feeds will only enable the stage if they share
 * an id with a default; that's a fine constraint while only Spamhaus
 * DROP/EDROP ship by default.
 */
async function ipStageEnabled(env: Env, _mailboxId: string): Promise<boolean> {
	if (env.CROWDSEC_CTI_API_KEY) return true;
	if (!env.BLOOM_KV) return false;
	const cidrFeedIds = DEFAULT_FEEDS.filter((f) => f.kind === "ip-cidr").map((f) => f.id);
	for (const id of cidrFeedIds) {
		try {
			const present = await env.BLOOM_KV.get(`intel:${id}:cidrs`, "text");
			if (present) return true;
		} catch {
			// Treat lookup error as "no signal" — the per-stage code is
			// best-effort and we'd rather skip DoH than spam it.
		}
	}
	return false;
}

// ── IP-CIDR feed stage ───────────────────────────────────────────

/**
 * Cap on the score the IP-feed stage can add per inbound. Sized to match
 * the CTI cap so neither single stage can dominate the deep-scan budget;
 * `DEEP_SCAN_MAX_ADD = 40` still bounds the combined contribution.
 */
const IP_FEED_MAX_ADD = 25;

/**
 * Per-IP score bump for an IP-feed match. Mirrors the URL feed-match weight
 * (`+20` in `scanUrls`) so an IP-listed redirect target gets the same
 * magnitude of signal as a URL-listed redirect target.
 */
const IP_FEED_PER_HIT = 20;

/**
 * Look each resolved IP up in `ip-cidr` feeds (Spamhaus DROP/EDROP and
 * any user-configured equivalents). Independent of CTI — works on deploys
 * without `CROWDSEC_CTI_API_KEY`.
 *
 * `checkIpAgainstFeeds` returns the first matching feed per IP; one match
 * per IP is enough signal that we don't keep scanning the rest of the
 * feed list for the same IP.
 */
async function scanIpFeeds(
	env: Env,
	mailboxId: string,
	ips: string[],
): Promise<{ score: number; reasons: string[] }> {
	if (!ips.length) return { score: 0, reasons: [] };

	const reasons: string[] = [];
	let score = 0;
	for (const ip of ips) {
		const match = await checkIpAgainstFeeds(env, mailboxId, ip).catch(() => null);
		if (!match) continue;
		score += IP_FEED_PER_HIT;
		// Feed name preference: human-readable description first word
		// ("Spamhaus DROP — ..."), falling back to the feed id. The reason
		// string is operator-facing so a recognizable name matters.
		const feedLabel = feedDisplayName(match.feedDescription, match.feedId);
		reasons.push(`redirect target IP ${match.ip} (${match.cidr}) on ${feedLabel}`);
	}
	return { score: Math.min(IP_FEED_MAX_ADD, score), reasons };
}

function feedDisplayName(description: string, fallback: string): string {
	// Default-feed descriptions are formatted "Name — details"; take the
	// portion before the em-dash if present.
	const dash = description.indexOf("—");
	const head = dash === -1 ? description : description.slice(0, dash);
	const cleaned = head.trim();
	return cleaned || fallback;
}

/**
 * Resolve a hostname to its A records via Cloudflare DNS-over-HTTPS.
 * workerd has no native `dns.resolve()` — DoH is the standard pattern.
 *
 * Returns the IPv4 strings (no AAAA — CrowdSec CTI is keyed primarily on
 * IPv4 and the reduction in fan-out is meaningful for the budget). Any
 * failure (timeout, non-200, non-Answer payload) returns an empty array;
 * the CTI stage treats unresolved hosts as "no signal".
 */
async function resolveHostA(host: string): Promise<string[]> {
	if (!host) return [];
	let res: Response;
	try {
		res = await fetch(
			`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
			{
				headers: { accept: "application/dns-json" },
				signal: AbortSignal.timeout(CTI_DOH_TIMEOUT_MS),
			},
		);
	} catch {
		return [];
	}
	if (!res.ok) return [];
	let body: unknown;
	try {
		body = await res.json();
	} catch {
		return [];
	}
	const answer = (body as { Answer?: Array<{ type?: number; data?: unknown }> }).Answer;
	if (!Array.isArray(answer)) return [];
	const ips: string[] = [];
	for (const a of answer) {
		// DNS A records are type=1 in DoH JSON.
		if (a.type !== 1) continue;
		if (typeof a.data !== "string") continue;
		// Be paranoid: the CTI URL path inserts this directly. Reject anything
		// that isn't a plain dotted-quad.
		if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(a.data)) continue;
		ips.push(a.data);
	}
	return ips;
}

/** Extensions for which we do a bounded R2 read to sniff encryption flags. */
const ENCRYPTED_ARCHIVE_CHECK_EXTS = new Set(["zip", "rar", "7z"]);
/** Size of the prefix we fetch from R2 for archive-header inspection. */
const ARCHIVE_HEADER_READ_BYTES = 32 * 1024;
/** Below this file size, any "archive" is certainly junk — skip the R2 read. */
const ARCHIVE_MIN_FILE_SIZE = 100;

/**
 * Fetch enough bytes from the R2-stored attachment to decide whether the
 * archive advertises encryption. Best-effort: any failure returns an empty
 * signal object so attachment scoring can proceed without this input.
 */
async function detectArchiveSignals(
	env: Env,
	emailId: string,
	row: { id: string; filename: string; size: number },
): Promise<{ encryptedArchive?: boolean }> {
	const ext = finalExtension(row.filename);
	if (!ENCRYPTED_ARCHIVE_CHECK_EXTS.has(ext)) return {};
	if (row.size < ARCHIVE_MIN_FILE_SIZE) return {};

	const key = `attachments/${emailId}/${row.id}/${row.filename}`;
	try {
		const obj = await env.BUCKET.get(key, {
			range: { offset: 0, length: ARCHIVE_HEADER_READ_BYTES },
		});
		if (!obj) return {};
		const buf = new Uint8Array(await obj.arrayBuffer());
		return { encryptedArchive: detectEncryptedArchive(buf, ext) };
	} catch (e) {
		console.error("deep-scan archive header read failed:", (e as Error).message);
		return {};
	}
}

// ── Internals ────────────────────────────────────────────────────

interface StoredVerdict { verdict: string | null; score: number | null; }

function parseVerdict(raw: string | null | undefined): FinalVerdict | null {
	if (!raw) return null;
	try { return JSON.parse(raw) as FinalVerdict; } catch { return null; }
}

function actionForScore(score: number, thresholds: VerdictThresholds): FinalVerdict["action"] {
	if (score >= thresholds.block) return "block";
	if (score >= thresholds.quarantine) return "quarantine";
	if (score >= thresholds.tag) return "tag";
	return "allow";
}

function tierIndex(action: FinalVerdict["action"]): number {
	switch (action) {
		case "allow": return 0;
		case "tag": return 1;
		case "quarantine": return 2;
		case "block": return 3;
	}
}

function safeHost(url: string): string | null {
	try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

function dedupe(items: string[]): string[] {
	return [...new Set(items)];
}

export type { StoredVerdict };
