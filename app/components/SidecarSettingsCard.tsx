// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Badge, Button, Input } from "@cloudflare/kumo";
import { useState } from "react";
import type { SidecarHealth, SidecarSettings } from "~/types";

export type SidecarFormValue = SidecarSettings;
export type { SidecarHealth };

const SECRET_NAME_PREFIX = "SIDECAR_SECRET_";

/**
 * Per-mailbox "Workspace sidecar" settings card (issue #31, Task 10). Scores
 * a mailbox's Google Workspace inbox via the Gmail API without an MX change.
 * Controlled component — the only network call it makes itself is the
 * connection test; save/remove flow entirely through `onChange` so the
 * parent's existing PUT-settings save path (with `stripDefaultEqual`
 * server-side) stays the single write path for this block.
 */
export function SidecarSettingsCard(props: {
	/** null = sidecar not configured (card shows an enable toggle) */
	value: SidecarFormValue | null;
	onChange: (v: SidecarFormValue | null) => void;
	health: SidecarHealth | null;
	/** true when the saved settings already contain a sidecar block —
	 *  gates the observe→active toggle (promotion only after first save) */
	savedConfigExists: boolean;
	mailboxId: string;
}) {
	const { value, onChange, health, savedConfigExists, mailboxId } = props;
	const [testResult, setTestResult] = useState<null | { ok: boolean; detail: string }>(null);
	const [testing, setTesting] = useState(false);

	const runTest = async () => {
		setTesting(true);
		setTestResult(null);
		try {
			const res = await fetch(`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/sidecar/test`, {
				method: "POST",
			});
			const data = (await res.json()) as {
				ok: boolean;
				emailAddress?: string;
				stage?: string;
				error?: string;
			};
			setTestResult(
				data.ok
					? { ok: true, detail: `Connected as ${data.emailAddress}` }
					: { ok: false, detail: `${data.stage}: ${data.error}` },
			);
		} catch (e) {
			setTestResult({ ok: false, detail: (e as Error).message });
		} finally {
			setTesting(false);
		}
	};

	const secretValid = !value || value.credentials_secret_name.startsWith(SECRET_NAME_PREFIX);

	if (!value) {
		return (
			<div className="pp-card p-5">
				<div className="text-sm font-medium text-ink mb-2">Workspace sidecar</div>
				<p className="text-xs text-ink-3 mb-4">
					Score this mailbox's Google Workspace inbox via the Gmail API — no MX
					change. See <code className="pp-mono">docs/sidecar-credentials.md</code>{" "}
					for the service-account setup.
				</p>
				<Button
					variant="secondary"
					size="sm"
					type="button"
					onClick={() =>
						onChange({
							provider: "workspace",
							credentials_secret_name: SECRET_NAME_PREFIX,
							mode: "observe",
							quarantine_behavior: "label-only",
							retention_days: 7,
						})
					}
				>
					Configure sidecar
				</Button>
			</div>
		);
	}

	return (
		<div className="pp-card p-5">
			<div className="flex items-center justify-between mb-3">
				<span className="text-sm font-medium text-ink inline-flex items-center gap-2">
					Workspace sidecar
					{health && (
						<span data-testid="sidecar-health-badge">
							<Badge variant={health.healthy ? "secondary" : "primary"}>
								{health.healthy ? "Healthy" : "Attention needed"}
							</Badge>
						</span>
					)}
				</span>
			</div>
			{health && (
				<p role="status" className="text-xs text-ink-3 mb-3">
					{health.healthy ? "● Healthy" : "▲ Attention needed"}
					{health.last_poll_at
						? ` — last poll ${new Date(health.last_poll_at).toLocaleString()}`
						: " — not polled yet"}
					{health.last_error ? ` — ${health.last_error}` : ""}
				</p>
			)}

			<div className="space-y-3">
				<Input
					label="Service-account secret name"
					value={value.credentials_secret_name}
					onChange={(e) => onChange({ ...value, credentials_secret_name: e.target.value })}
					placeholder="SIDECAR_SECRET_yourorg"
					aria-invalid={!secretValid}
				/>
				{!secretValid && (
					<p role="alert" className="text-xs text-red-600 dark:text-red-400">
						Secret name must start with {SECRET_NAME_PREFIX}.
					</p>
				)}
				<p className="text-xs text-ink-3">
					The service-account JSON itself lives in a Worker secret (
					<code className="pp-mono">wrangler secret put &lt;name&gt;</code>), never
					in settings.
				</p>

				<div>
					<label htmlFor="sidecar-mode-select" className="block text-sm text-ink mb-1.5">
						Mode
					</label>
					<select
						id="sidecar-mode-select"
						value={value.mode ?? "observe"}
						disabled={!savedConfigExists}
						onChange={(e) =>
							onChange({ ...value, mode: e.target.value as "observe" | "active" })
						}
						className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-60"
					>
						<option value="observe">Observe only (record verdicts, write nothing)</option>
						<option value="active">Active (write PhishPilot labels to the inbox)</option>
					</select>
					{!savedConfigExists && (
						<p className="text-xs text-ink-3 mt-2">
							New sidecar mailboxes start in observe mode. Save first, review the
							verdict mix, then promote.
						</p>
					)}
				</div>

				<div>
					<label htmlFor="sidecar-quarantine-select" className="block text-sm text-ink mb-1.5">
						Quarantine behavior
					</label>
					<select
						id="sidecar-quarantine-select"
						value={value.quarantine_behavior ?? "label-only"}
						onChange={(e) =>
							onChange({
								...value,
								quarantine_behavior: e.target.value as "label-only" | "label-and-archive",
							})
						}
						className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-accent"
					>
						<option value="label-only">Label only</option>
						<option value="label-and-archive">Label and archive (remove from Inbox)</option>
					</select>
				</div>

				<Input
					label="Body retention (days, 0 = keep forever)"
					type="number"
					min={0}
					value={value.retention_days ?? 7}
					onChange={(e) =>
						onChange({ ...value, retention_days: Math.max(0, Number(e.target.value) || 0) })
					}
				/>

				<div className="flex items-center justify-between pt-2 border-t border-line">
					<div className="flex items-center gap-2">
						<Button
							variant="secondary"
							size="sm"
							type="button"
							onClick={runTest}
							loading={testing}
							disabled={!secretValid}
						>
							Test connection
						</Button>
						{testResult && (
							<span
								role={testResult.ok ? "status" : "alert"}
								className={`text-xs ${testResult.ok ? "text-ink-3" : "text-red-600 dark:text-red-400"}`}
							>
								{testResult.detail}
							</span>
						)}
					</div>
					<Button variant="ghost" size="sm" type="button" onClick={() => onChange(null)}>
						Remove sidecar config
					</Button>
				</div>
			</div>
		</div>
	);
}
