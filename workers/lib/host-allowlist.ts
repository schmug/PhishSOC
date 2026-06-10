// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Destination host allowlisting for credential-bearing outbound fetches
 * (GHSA-jfj6-w954-96vg, findings f29 hub / f27 feed).
 *
 * The `HUB_SECRET_` / `FEED_SECRET_` name-prefix guards constrain WHICH
 * worker secret a teammate-editable settings blob may reference, but not
 * WHERE the resolved secret is sent. Destination URLs (`intel.hub.url`,
 * `intel.feeds[].url`) live in org/mailbox settings that any authenticated
 * teammate can edit — so the secret must additionally be pinned to an
 * operator-controlled hostname allowlist supplied via worker env vars
 * (`HUB_ALLOWED_HOSTS` / `FEED_ALLOWED_HOSTS`), which settings edits
 * cannot touch.
 */

/**
 * Returns true only when `url` parses, uses `https:`, and its hostname is
 * present (case-insensitive, exact match) in the union of the
 * comma-separated `allowedCsv` allowlist and `extraHosts`.
 *
 * Defensive by design: a malformed URL, a non-https scheme, or an
 * unset/empty allowlist all yield `false` — the caller must treat that as
 * "do not send the credential".
 */
export function hostAllowed(
	url: string,
	allowedCsv: string | undefined,
	extraHosts: string[] = [],
): boolean {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return false;
	}
	if (parsed.protocol !== "https:") return false;
	const host = parsed.hostname.toLowerCase();

	const allowed = new Set<string>();
	for (const extra of extraHosts) {
		const t = extra.trim().toLowerCase();
		if (t) allowed.add(t);
	}
	for (const entry of (allowedCsv ?? "").split(",")) {
		const t = entry.trim().toLowerCase();
		if (t) allowed.add(t);
	}
	return allowed.has(host);
}
