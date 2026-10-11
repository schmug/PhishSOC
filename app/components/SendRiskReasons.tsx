// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Why the send-risk preflight picked its tier — shown next to the send
 * controls so a tier-2 "type the recipient" prompt says what it is guarding
 * against (a lookalike domain, a reply to a flagged message, ...).
 */
export default function SendRiskReasons({ reasons }: { reasons?: string[] | null }) {
	if (!reasons || reasons.length === 0) return null;
	return (
		<ul className="mt-2 text-xs text-ink-3 list-disc ml-4 space-y-0.5" data-testid="send-risk-reasons">
			{reasons.map((reason, i) => (
				<li key={i}>{reason}</li>
			))}
		</ul>
	);
}
