// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Body string for outbound send-risk classification and step-up token binding.
 *
 * When both MIME parts are present, both must be scanned. Using `html || text`
 * lets an API caller place BEC keywords in text/plain while the classifier
 * only reads text/html.
 */
export function combinedSendBodyForRisk(
	html?: string | null,
	text?: string | null,
): string {
	const parts: string[] = [];
	if (html) parts.push(html);
	if (text) parts.push(text);
	return parts.join("\n");
}
