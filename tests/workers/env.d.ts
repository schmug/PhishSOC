// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Types for the `cloudflare:test` env used by the workers-pool suite (#376).
import type { D1Migration } from "@cloudflare/vitest-pool-workers/config";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		WEBAUTHN_DB: D1Database;
		RP_ID: string;
		RP_ORIGIN: string;
		TEST_MIGRATIONS: D1Migration[];
	}
}
