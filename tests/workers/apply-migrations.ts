// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Workers-pool setup: apply the migrations/webauthn schema to the in-memory
// test D1 once per suite. TEST_MIGRATIONS is injected by vitest.workers.config.ts
// via readD1Migrations(); applyD1Migrations runs them against WEBAUTHN_DB. The
// isolated-storage stack snapshots after this runs, so every test sees the
// schema with no leftover rows.
import { applyD1Migrations, env } from "cloudflare:test";
import { beforeAll } from "vitest";

beforeAll(async () => {
	await applyD1Migrations(env.WEBAUTHN_DB, env.TEST_MIGRATIONS);
});
