// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Provider registry.
 *
 * `getProvider(env, mailboxId?)` returns the configured MailProvider for
 * outbound delivery.  The default is `ResendProvider` (Cloudflare Email
 * Service).  Per-mailbox overrides are not yet wired — they will be added
 * when the first alternative outbound provider (Workspace send-as, M365
 * Graph) ships.
 *
 * Adding a new outbound provider:
 *   1. Create `workers/providers/<name>.ts` implementing `MailProvider`.
 *   2. Import it here and add the per-mailbox lookup logic.
 *   3. No edits to workers/security/, workers/intel/, or workers/agent/.
 */

import { ResendProvider } from "./resend";
import type { MailProvider } from "./types";

const _default = new ResendProvider();

/**
 * Return the outbound MailProvider for the given mailbox (or the global
 * default when no mailboxId is supplied).
 */
export function getProvider(_mailboxId?: string): MailProvider {
	// Future: look up per-mailbox provider config from DO settings.
	return _default;
}
