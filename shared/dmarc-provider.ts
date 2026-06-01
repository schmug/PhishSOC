// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Static PTR-suffix → provider name map for DMARC sender attribution.
 *
 * Checked longest-suffix-first so more-specific entries win
 * (e.g. `mail.protection.outlook.com` matches before `outlook.com`).
 */
const PTR_SUFFIXES: Array<[suffix: string, provider: string]> = [
	[".mail.protection.outlook.com", "Microsoft 365"],
	[".google.com", "Google"],
	[".googlemail.com", "Google"],
	[".outlook.com", "Microsoft 365"],
	[".microsoft.com", "Microsoft 365"],
	[".hotmail.com", "Microsoft 365"],
	[".sendgrid.net", "SendGrid"],
	[".amazonaws.com", "Amazon SES"],
	[".mailgun.org", "Mailgun"],
	[".sparkpostmail.com", "SparkPost"],
	[".mcsv.net", "Mailchimp"],
	[".rsgsv.net", "Mailchimp"],
	[".constantcontact.com", "Constant Contact"],
	[".salesforce.com", "Salesforce Marketing Cloud"],
	[".exacttarget.com", "Salesforce Marketing Cloud"],
	[".zendesk.com", "Zendesk"],
	[".postmarkapp.com", "Postmark"],
	[".mandrill.com", "Mailchimp Transactional"],
];

/**
 * Given a PTR-resolved hostname, return a human-readable provider name or null.
 * Comparison is case-insensitive.
 */
export function classifyProvider(hostname: string): string | null {
	const lower = hostname.toLowerCase();
	for (const [suffix, provider] of PTR_SUFFIXES) {
		// Match either exact (hostname == suffix without leading dot) or as a suffix.
		if (lower === suffix.slice(1) || lower.endsWith(suffix)) return provider;
	}
	return null;
}

/**
 * Build the label to persist in `dmarc_sources.label`:
 * - known ESP → provider name ("Google", "SendGrid", …)
 * - unknown PTR → the hostname itself
 * - no PTR → null
 */
export function buildDmarcSourceLabel(hostname: string | null): string | null {
	if (!hostname) return null;
	return classifyProvider(hostname) ?? hostname;
}
