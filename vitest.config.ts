import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

/**
 * Three suites live side-by-side:
 *   - `tests/**` (excluding `tests/frontend/**`) — pure-function unit tests
 *     (parsing, scoring, aggregation). No Workers runtime required.
 *   - `test/**`  — integration harness that drives `runSecurityPipeline`
 *     end-to-end against in-memory fakes for Env bindings. Uses the default
 *     Node pool; the fakes are sufficient and spinning up the real Workers
 *     runtime would only slow CI.
 *   - `tests/frontend/**` — React component / hook tests under jsdom, with
 *     React Testing Library. The `~/` alias mirrors `tsconfig.cloudflare.json`.
 *   - `tests/workers/**` — real-`workerd` tests via @cloudflare/vitest-pool-workers
 *     (issue #376). Defined in vitest.workers.config.ts so the D1 store and the
 *     WebAuthn verify path exercise the production runtime, not a Node fake.
 */
export default defineConfig({
	// `tsconfig.cloudflare.json` sets `jsx: "react-jsx"` but lives behind a
	// project reference vite/esbuild doesn't follow — opt in explicitly so
	// `.tsx` test files don't need a `React` import for JSX.
	esbuild: {
		jsx: "automatic",
	},
	// Mirror the path mappings from `tsconfig.cloudflare.json` (`~/*` → `./app/*`)
	// and the `baseUrl: "."` resolution that lets workers/app code import
	// `shared/...` without a relative path.
	resolve: {
		alias: {
			"~": fileURLToPath(new URL("./app", import.meta.url)),
			shared: fileURLToPath(new URL("./shared", import.meta.url)),
		},
	},
	test: {
		reporters: ["default"],
		testTimeout: 10000,
		projects: [
			{
				extends: true,
				test: {
					name: "node",
					include: ["tests/**/*.test.ts", "test/**/*.test.ts"],
					// tests/workers/** run in the workers pool (vitest.workers.config.ts);
					// they import `cloudflare:test`, unavailable in the node pool.
					exclude: ["tests/frontend/**", "tests/workers/**"],
					environment: "node",
					globals: false,
					pool: "forks",
				},
			},
			{
				extends: true,
				test: {
					name: "frontend",
					include: ["tests/frontend/**/*.test.{ts,tsx}"],
					environment: "jsdom",
					globals: false,
					setupFiles: ["./tests/frontend/setup.ts"],
				},
			},
			// Real-workerd suite (issue #376) — its own config because the
			// pool, compat flags, and test D1 differ from the node/jsdom pools.
			"./vitest.workers.config.ts",
		],
	},
});
