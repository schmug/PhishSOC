import { fileURLToPath } from "node:url";
import {
	cloudflareTest,
	readD1Migrations,
} from "@cloudflare/vitest-pool-workers";
import { defineProject } from "vitest/config";

/**
 * Workers-pool test project (issue #376). Unlike the `node`/`frontend`
 * projects in vitest.config.ts, these tests run inside real `workerd` via
 * `@cloudflare/vitest-pool-workers` so the D1 store (`DELETE … RETURNING`
 * atomicity) and the `@simplewebauthn/server` verify path (`crypto.subtle`
 * ES256) behave exactly as they do in production.
 *
 * Migrations from migrations/webauthn are read at config time, passed in as
 * the TEST_MIGRATIONS binding, and applied to the in-memory test D1 by
 * tests/workers/apply-migrations.ts before each suite.
 *
 * `cloudflareTest()` is the vitest-4 plugin form (was `defineWorkersProject`
 * + `poolOptions.workers` in the vitest-3 line).
 */
export default defineProject(async () => {
	const migrations = await readD1Migrations(
		fileURLToPath(new URL("./migrations/webauthn", import.meta.url)),
	);

	return {
		plugins: [
			cloudflareTest({
				singleWorker: true,
				miniflare: {
					compatibilityDate: "2025-11-28",
					compatibilityFlags: ["nodejs_compat"],
					d1Databases: { WEBAUTHN_DB: "webauthn-test" },
					bindings: {
						RP_ID: "localhost",
						RP_ORIGIN: "http://localhost:5173",
						TEST_MIGRATIONS: migrations,
					},
				},
			}),
		],
		resolve: {
			alias: {
				"~": fileURLToPath(new URL("./app", import.meta.url)),
				shared: fileURLToPath(new URL("./shared", import.meta.url)),
			},
		},
		test: {
			name: "workers",
			include: ["tests/workers/**/*.test.ts"],
			setupFiles: ["./tests/workers/apply-migrations.ts"],
		},
	};
});
