/**
 * Static map of PTR-suffix patterns to human-readable sending-provider names.
 * Entries are checked longest-first so `.mail.protection.outlook.com` wins
 * over `.outlook.com`.
 */
export const PTR_PROVIDER_SUFFIXES: ReadonlyArray<{ suffix: string; name: string }> = [
	{ suffix: ".mail.protection.outlook.com", name: "Microsoft 365" },
	{ suffix: ".outbound.protection.outlook.com", name: "Microsoft 365" },
	{ suffix: ".protection.outlook.com", name: "Microsoft 365" },
	{ suffix: ".outlook.com", name: "Microsoft 365" },
	{ suffix: ".google.com", name: "Google" },
	{ suffix: ".googlemail.com", name: "Google" },
	{ suffix: ".gmail.com", name: "Google" },
	{ suffix: ".sendgrid.net", name: "SendGrid" },
	{ suffix: ".amazonses.com", name: "Amazon SES" },
	{ suffix: ".mailgun.org", name: "Mailgun" },
	{ suffix: ".mailchimpapp.net", name: "Mailchimp" },
	{ suffix: ".mandrillapp.com", name: "Mailchimp/Mandrill" },
	{ suffix: ".postmarkapp.com", name: "Postmark" },
	{ suffix: ".sparkpostmail.com", name: "SparkPost" },
	{ suffix: ".mailjet.net", name: "Mailjet" },
	{ suffix: ".sendinblue.com", name: "Brevo/Sendinblue" },
	{ suffix: ".smtp.com", name: "SMTP.com" },
	{ suffix: ".exacttarget.com", name: "Salesforce Marketing Cloud" },
	{ suffix: ".salesforce.com", name: "Salesforce" },
	{ suffix: ".hubspotemail.net", name: "HubSpot" },
	{ suffix: ".constant-content.com", name: "Constant Contact" },
	{ suffix: ".mimecast.com", name: "Mimecast" },
	{ suffix: ".proofpoint.com", name: "Proofpoint" },
];

/**
 * Given a PTR hostname (trailing dot already stripped), return a provider name
 * if the hostname matches a known suffix, or null.
 */
export function matchProviderByPtr(ptr: string): string | null {
	const lower = ptr.toLowerCase();
	for (const { suffix, name } of PTR_PROVIDER_SUFFIXES) {
		if (lower.endsWith(suffix)) return name;
	}
	return null;
}
