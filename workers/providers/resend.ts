// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Outbound provider backed by Cloudflare Email Service (`send_email` binding).
 *
 * This is the default outbound provider.  Existing callers that import
 * `sendEmail` from `../email-sender` continue to work unchanged — they
 * indirectly use this provider.  New code should prefer calling
 * `getProvider(env, mailboxId).send(env, msg)` via the registry.
 */

import { sendEmail } from "../email-sender";
import type { Env } from "../types";
import type { MailProvider, NormalizedOutbound } from "./types";

export class ResendProvider implements MailProvider {
	readonly id = "cf-email-service";

	async send(env: Env, msg: NormalizedOutbound): Promise<{ messageId: string }> {
		return sendEmail(env.EMAIL, msg);
	}
}
