// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import type { Env } from "../types";
import type { GatewayInbound } from "../providers/types";

export async function receiveGatewayPassthrough(
	normalized: GatewayInbound,
	_env: Env,
	_ctx: ExecutionContext,
): Promise<void> {
	// Implemented in the next commit (Task 12): stateless scan → tag-cap → relay.
	console.error("receiveGatewayPassthrough not yet implemented; dropping", normalized.recipient);
}
