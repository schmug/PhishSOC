// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Button, Input } from "@cloudflare/kumo";
import { useCallback, useEffect, useState } from "react";
import { DEFAULT_REJECT_REASON, type BlockAction, type BlockRule } from "shared/blocklist";
import api, { ApiError, type BlockedLogRow, type BlocklistScope } from "~/services/api";

type Tier = "mailbox" | "domain" | "org";

interface Row {
	tier: Tier;
	rule: BlockRule;
}

const ACTION_LABELS: Record<BlockAction, string> = {
	spam: "Move to Spam",
	drop: "Drop silently",
	reject: "Bounce",
};

/**
 * Blocked senders list for one settings tier (spec
 * 2026-09-27-sender-blocklist). Rules at this tier are removable; the mailbox
 * tier also shows inherited domain/org rules read-only plus the recent
 * drop/reject audit log. Writes go only through the /blocklist endpoints —
 * the page's settings form never carries `blocklist`.
 */
export function BlockedSendersPanel({
	tier,
	mailboxId,
	domain,
}: {
	tier: Tier;
	mailboxId?: string;
	domain?: string;
}) {
	const scope = blocklistScope(tier, mailboxId, domain);
	const [rows, setRows] = useState<Row[]>([]);
	const [log, setLog] = useState<BlockedLogRow[]>([]);
	const [loaded, setLoaded] = useState(false);
	const [match, setMatch] = useState("");
	const [action, setAction] = useState<BlockAction>("spam");
	const [reason, setReason] = useState(DEFAULT_REJECT_REASON);
	const [error, setError] = useState<string | null>(null);
	const [pending, setPending] = useState(false);

	const load = useCallback(async () => {
		if (!scope) return;
		try {
			if (scope.tier === "mailbox") {
				const { settings } = await api.getEffectiveMailboxSettings(scope.mailboxId);
				const s = settings as { raw?: TierBlob; domain?: TierBlob; org?: TierBlob };
				setRows([
					...tierRows("mailbox", s.raw),
					...tierRows("domain", s.domain),
					...tierRows("org", s.org),
				]);
				setLog((await api.getBlockedLog(scope.mailboxId, 50).catch(() => ({ rows: [] }))).rows);
			} else if (scope.tier === "org") {
				setRows(tierRows("org", (await api.getOrgSettings()).settings as TierBlob));
			} else {
				setRows(tierRows("domain", (await api.getDomainSettings(scope.domain)).settings as TierBlob));
			}
		} catch {
			setError("Could not load blocked senders.");
		} finally {
			setLoaded(true);
		}
		// scope is derived from these three props.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [tier, mailboxId, domain]);

	useEffect(() => {
		void load();
	}, [load]);

	const remove = async (rule: BlockRule) => {
		if (!scope) return;
		setError(null);
		try {
			await api.removeBlockRule(scope, rule.id);
		} catch (err) {
			if (!(err instanceof ApiError && err.status === 404)) {
				setError(`Remove failed: ${(err as Error).message}`);
				return;
			}
		}
		setRows((prev) => prev.filter((r) => !(r.tier === tier && r.rule.id === rule.id)));
	};

	const add = async (e: React.FormEvent) => {
		e.preventDefault();
		if (!scope || !match.trim()) return;
		setPending(true);
		setError(null);
		try {
			const body: Record<string, unknown> = { match: match.trim(), action };
			if (action === "reject") body.reason = reason;
			const added = (await api.addBlockRule(scope, body)).rule;
			setRows((prev) => [
				...prev.filter((r) => !(r.tier === tier && r.rule.match === added.match)),
				{ tier, rule: added },
			]);
			setMatch("");
		} catch (err) {
			setError((err as Error).message);
		} finally {
			setPending(false);
		}
	};

	return (
		<section className="space-y-3" aria-label="Blocked senders">
			<div>
				<h3 className="text-sm font-semibold text-ink">Blocked senders</h3>
				<p className="text-xs text-ink-3">
					Mail from these senders is moved to Spam, dropped silently, or bounced before it is stored.
					{tier === "mailbox" ? " Domain and org rules are inherited and edited on their own settings pages." : ""}
				</p>
			</div>

			{loaded && rows.length === 0 ? (
				<p className="text-xs text-ink-3">No blocked senders.</p>
			) : null}
			{rows.length > 0 ? (
				<table aria-label="Block rules" className="w-full text-[13px]">
					<thead>
						<tr className="text-left text-xs text-ink-3">
							<th className="py-1 font-medium">Tier</th>
							<th className="py-1 font-medium">Sender or domain</th>
							<th className="py-1 font-medium">Action</th>
							<th className="py-1 font-medium">Added</th>
							<th className="py-1" />
						</tr>
					</thead>
					<tbody>
						{rows.map(({ tier: rowTier, rule }) => (
							<tr key={`${rowTier}-${rule.id}`} className="border-t border-line">
								<td className="py-1.5">
									<span className="text-xs rounded-full bg-paper-3 px-1.5 py-0.5 text-ink-3">{rowTier}</span>
								</td>
								<td className="py-1.5 text-ink">{rule.match}</td>
								<td className="py-1.5 text-ink-2">{ACTION_LABELS[rule.action] ?? rule.action}</td>
								<td className="py-1.5 text-ink-3">{rule.created_at.slice(0, 10)}</td>
								<td className="py-1.5 text-right">
									{rowTier === tier ? (
										<Button
											variant="ghost"
											size="sm"
											onClick={() => void remove(rule)}
											aria-label={`Remove ${rule.match}`}
										>
											Remove
										</Button>
									) : null}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			) : null}

			<form onSubmit={add} className="flex flex-wrap items-end gap-2">
				<div className="min-w-[220px] flex-1">
					<Input
						aria-label="Sender or domain"
						placeholder="spammer@example.com or example.com"
						size="sm"
						value={match}
						onChange={(e) => setMatch(e.target.value)}
					/>
				</div>
				<select
					aria-label="Action"
					value={action}
					onChange={(e) => setAction(e.target.value as BlockAction)}
					className="h-8 rounded-md border border-line bg-paper px-2 text-[13px] text-ink"
				>
					<option value="spam">Move to Spam</option>
					<option value="drop">Drop silently</option>
					<option value="reject">Bounce with message</option>
				</select>
				<Button type="submit" variant="secondary" size="sm" loading={pending} disabled={pending || !match.trim()}>
					Add rule
				</Button>
				{action === "reject" ? (
					<textarea
						aria-label="Bounce message"
						maxLength={200}
						rows={2}
						value={reason}
						onChange={(e) => setReason(e.target.value)}
						className="w-full rounded-md border border-line bg-paper px-3 py-2 text-[13px] text-ink"
					/>
				) : null}
			</form>
			{error ? <p className="text-xs text-red-600">{error}</p> : null}

			{tier === "mailbox" && log.length > 0 ? (
				<div>
					<h4 className="text-xs font-medium text-ink-3 mb-1">Recently dropped or bounced</h4>
					<table aria-label="Recently blocked" className="w-full text-xs">
						<tbody>
							{log.map((r) => (
								<tr key={r.id} className="border-t border-line">
									<td className="py-1 text-ink-3">{r.ts.slice(0, 16).replace("T", " ")}</td>
									<td className="py-1 text-ink-2">{r.sender}</td>
									<td className="py-1 text-ink">{r.subject}</td>
									<td className="py-1 text-ink-3">{r.action}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			) : null}
		</section>
	);
}

type TierBlob = { blocklist?: BlockRule[] } | undefined;

function tierRows(tier: Tier, blob: TierBlob): Row[] {
	return Array.isArray(blob?.blocklist) ? blob.blocklist.map((rule) => ({ tier, rule })) : [];
}

function blocklistScope(tier: Tier, mailboxId?: string, domain?: string): BlocklistScope | null {
	if (tier === "org") return { tier: "org" };
	if (tier === "domain") return domain ? { tier: "domain", domain } : null;
	return mailboxId ? { tier: "mailbox", mailboxId } : null;
}
