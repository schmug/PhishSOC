// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Badge } from "@cloudflare/kumo";
import { XIcon, WarningIcon, ShieldCheckIcon, LinkIcon } from "@phosphor-icons/react";
import { useEmailUrls } from "~/queries/emails";
import type { EmailUrl } from "~/types";

interface SafeLinkInspectorProps {
	/** The raw href from the clicked anchor tag. */
	href: string;
	emailId: string;
	mailboxId: string;
	onClose: () => void;
}

function safeHostname(url: string): string | null {
	try {
		return new URL(url).hostname;
	} catch {
		return null;
	}
}

function VerdictBadge({ verdict }: { verdict: string | null }) {
	if (!verdict) return <Badge variant="outline">Pending</Badge>;
	const v = verdict.toLowerCase();
	if (v.includes("phish") || v.includes("malicious") || v.includes("block"))
		return <Badge variant="destructive">{verdict}</Badge>;
	if (v.includes("suspicious") || v.includes("suspect"))
		return <Badge variant="secondary">{verdict}</Badge>;
	if (v.includes("clean") || v.includes("safe") || v.includes("allow"))
		return <Badge variant="success">{verdict}</Badge>;
	return <Badge variant="outline">{verdict}</Badge>;
}

function UrlRow({ urlData, clickedHref }: { urlData: EmailUrl; clickedHref: string }) {
	const startHost = safeHostname(urlData.url);
	const endHost = urlData.resolved_url ? safeHostname(urlData.resolved_url) : null;
	const hostChanged = startHost && endHost && startHost !== endHost;
	const hasFinalUrl = urlData.resolved_url && urlData.resolved_url !== urlData.url;

	return (
		<div className="space-y-3">
			<div>
				<div className="text-xs font-medium text-ink-3 mb-1">Clicked URL</div>
				<div className="font-mono text-xs break-all text-ink bg-paper-2 rounded p-2">
					{clickedHref}
				</div>
			</div>

			{hasFinalUrl && (
				<div>
					<div className="text-xs font-medium text-ink-3 mb-1">
						Final destination
						{hostChanged && (
							<span className="ml-2 text-warning font-semibold">
								(host changed!)
							</span>
						)}
					</div>
					<div className="font-mono text-xs break-all text-ink bg-paper-2 rounded p-2">
						{urlData.resolved_url}
					</div>
				</div>
			)}

			{urlData.page_title && (
				<div>
					<div className="text-xs font-medium text-ink-3 mb-1">Page title</div>
					<div className="text-sm text-ink truncate">{urlData.page_title}</div>
				</div>
			)}

			<div className="flex items-center gap-3 flex-wrap">
				<div className="flex items-center gap-1.5">
					<span className="text-xs text-ink-3">Verdict:</span>
					<VerdictBadge verdict={urlData.verdict} />
				</div>
				{!!urlData.is_homograph && (
					<Badge variant="destructive">Homograph domain</Badge>
				)}
				{!!urlData.is_shortener && (
					<Badge variant="secondary">URL shortener</Badge>
				)}
			</div>
		</div>
	);
}

export default function SafeLinkInspector({
	href,
	emailId,
	mailboxId,
	onClose,
}: SafeLinkInspectorProps) {
	const { data, isLoading } = useEmailUrls(mailboxId, emailId);

	const urlData = data?.urls.find((u) => {
		try {
			// Normalise both sides before comparing so trailing slashes and
			// minor encoding differences don't produce false misses.
			return new URL(u.url).href === new URL(href).href;
		} catch {
			return u.url === href;
		}
	});

	return (
		<div className="border border-line rounded-lg bg-paper shadow-sm">
			<div className="flex items-center justify-between px-4 py-3 border-b border-line">
				<div className="flex items-center gap-2">
					<ShieldCheckIcon size={16} className="text-ink-3" />
					<span className="text-sm font-medium text-ink">Link inspector</span>
				</div>
				<button
					type="button"
					onClick={onClose}
					className="text-ink-3 hover:text-ink transition-colors"
					aria-label="Close link inspector"
				>
					<XIcon size={16} />
				</button>
			</div>

			<div className="px-4 py-4">
				{isLoading ? (
					<div className="text-sm text-ink-3">Loading scan data…</div>
				) : urlData ? (
					<UrlRow urlData={urlData} clickedHref={href} />
				) : (
					<div className="space-y-3">
						<div>
							<div className="text-xs font-medium text-ink-3 mb-1">Clicked URL</div>
							<div className="font-mono text-xs break-all text-ink bg-paper-2 rounded p-2">
								{href}
							</div>
						</div>
						<div className="flex items-center gap-1.5 text-xs text-ink-3">
							<LinkIcon size={12} />
							<span>No scan data available for this link.</span>
						</div>
					</div>
				)}

				<div className="mt-4 pt-3 border-t border-line">
					<div className="flex items-start gap-1.5 text-xs text-ink-3">
						<WarningIcon size={12} className="mt-0.5 shrink-0" />
						<span>
							Links in emails are never opened directly. Use this data to assess
							the destination before taking any action.
						</span>
					</div>
				</div>
			</div>
		</div>
	);
}
