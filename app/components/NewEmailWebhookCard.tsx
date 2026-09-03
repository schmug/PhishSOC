// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Button, Input } from "@cloudflare/kumo";
import { useState } from "react";
import api from "~/services/api";
import { NEW_EMAIL_WEBHOOK_SECRET_PREFIX } from "shared/mailbox-settings";
import type { NewEmailWebhookSettings } from "shared/mailbox-settings";

export type NewEmailWebhookTier = "mailbox" | "domain" | "org";

/**
 * The three states a `newEmailWebhook` block can express. Unlike every other
 * settings toggle this block is NOT a boolean:
 *
 *   inherit    key absent / `{}`      fall through to the next tier, then the
 *                                     deployment-wide `NEW_EMAIL_WEBHOOK_URL`
 *   muted      `{enabled:false}`      this scope stays silent — no fall-through
 *   configured `{enabled:true, urlSecret}`  post to that secret's URL
 *
 * A boolean control collapses inherit and muted into one state and leaves
 * muting unreachable, which is why the card renders a radio group.
 * `stripDefaultEqual` (`workers/lib/mailbox-settings.ts`) strips only `{}` for
 * this key — never `{enabled:false}` — so a written mute persists.
 */
export type NewEmailWebhookMode = "inherit" | "muted" | "configured";

/**
 * Classify a stored block. A half-written block (`urlSecret` with no explicit
 * `enabled: true`) reads as muted, matching `resolveNewEmailWebhook`: an
 * outbound flow of mail metadata never starts from an implicit enable.
 */
export function newEmailWebhookMode(
	value: NewEmailWebhookSettings | undefined,
): NewEmailWebhookMode {
	if (!value || Object.keys(value).length === 0) return "inherit";
	return value.enabled === true ? "configured" : "muted";
}

/**
 * Client-side mirror of the schema's `startsWith` guard on `urlSecret`. The
 * prefix stops a settings write from naming an unrelated secret
 * (`CONFIRMATION_TOKEN_SECRET`, `HUB_API_KEY`) and having its value POSTed to
 * an operator-chosen endpoint — the confused-deputy hole `RELAY_CREDS_`
 * closed in #615. Routes call this before their PUT so a bad name is caught
 * before the round trip, not after.
 */
export function isNewEmailWebhookValid(
	value: NewEmailWebhookSettings | undefined,
): boolean {
	if (newEmailWebhookMode(value) !== "configured") return true;
	return (value?.urlSecret ?? "").startsWith(NEW_EMAIL_WEBHOOK_SECRET_PREFIX);
}

/** What "inherit" actually falls through to, per tier. */
const INHERIT_COPY: Record<NewEmailWebhookTier, string> = {
	mailbox:
		"Fall through to the domain, then the org, then the deployment-wide webhook.",
	domain: "Fall through to the org, then the deployment-wide webhook.",
	org: "Fall through to the deployment-wide webhook.",
};

/** What this scope covers, per tier — used in the mute description. */
const SCOPE_COPY: Record<NewEmailWebhookTier, string> = {
	mailbox: "this mailbox",
	domain: "every mailbox under this domain",
	org: "every mailbox in the org",
};

/**
 * Shared "New mail webhook" settings section, rendered by all three tier
 * routes (`app/routes/settings.tsx`, `domain-settings.tsx`,
 * `org-settings.tsx`).
 *
 * Controlled component: `undefined` means inherit, and the parent writes the
 * key only when a block is present. The field holds the NAME of a Worker
 * Secret and never the URL — settings blobs are returned to any
 * Access-authenticated client by the settings GET endpoints, and a chat
 * webhook URL is a bearer credential (a Google Chat webhook carries its `key`
 * and `token` in the query string).
 */
export function NewEmailWebhookCard(props: {
	/** undefined = inherit (the parent omits the key on save) */
	value: NewEmailWebhookSettings | undefined;
	onChange: (next: NewEmailWebhookSettings | undefined) => void;
	tier: NewEmailWebhookTier;
}) {
	const { value, onChange, tier } = props;
	// Remembers a typed name across a mute/inherit detour so toggling back to
	// "configured" doesn't wipe what the operator already entered.
	const [secretDraft, setSecretDraft] = useState(
		value?.urlSecret || NEW_EMAIL_WEBHOOK_SECRET_PREFIX,
	);

	// Result of the last "Send test", cleared whenever the draft changes below —
	// a stale "Delivered" sitting next to an edited secret name reads as a pass
	// for a config that was never tested.
	const [testing, setTesting] = useState(false);
	const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(null);

	const mode = newEmailWebhookMode(value);
	const secretInvalid = mode === "configured" && !isNewEmailWebhookValid(value);

	/**
	 * Post the DRAFT block, not the saved one, so a secret name can be verified
	 * before it is committed — which is when the typo happens. The endpoint
	 * resolves the destination from the named Worker Secret server-side; the
	 * URL never travels in either direction.
	 */
	const runTest = async () => {
		setTesting(true);
		setTestResult(null);
		try {
			const data = await api.testNewEmailWebhook({
				urlSecret: value?.urlSecret ?? "",
				...(value?.format ? { format: value.format } : {}),
				tier,
			});
			setTestResult(
				data.ok
					? { ok: true, detail: `Delivered — the endpoint returned HTTP ${data.status}.` }
					: { ok: false, detail: `${data.stage}: ${data.error}` },
			);
		} catch (e) {
			setTestResult({ ok: false, detail: (e as Error).message });
		} finally {
			setTesting(false);
		}
	};

	const selectMode = (next: NewEmailWebhookMode) => {
		if (next === "inherit") {
			onChange(undefined);
			return;
		}
		if (next === "muted") {
			onChange({ enabled: false });
			return;
		}
		onChange({
			...value,
			enabled: true,
			urlSecret: secretDraft || NEW_EMAIL_WEBHOOK_SECRET_PREFIX,
		});
	};

	const option = (
		next: NewEmailWebhookMode,
		title: string,
		description: string,
	) => (
		<label
			htmlFor={`new-email-webhook-${tier}-${next}`}
			className="flex items-start gap-3 cursor-pointer"
		>
			<input
				id={`new-email-webhook-${tier}-${next}`}
				type="radio"
				name={`new-email-webhook-${tier}-mode`}
				checked={mode === next}
				onChange={() => selectMode(next)}
				className="mt-1 h-4 w-4 accent-accent shrink-0"
			/>
			<span className="flex flex-col">
				<span className="text-sm text-ink">{title}</span>
				<span className="text-xs text-ink-3 mt-0.5 max-w-md">{description}</span>
			</span>
		</label>
	);

	return (
		<div className="pp-card p-5">
			<div className="text-sm font-medium text-ink mb-2">New mail webhook</div>
			<p className="text-xs text-ink-3 mb-4 max-w-xl">
				Post a chat message when mail arrives. Most specific tier wins —{" "}
				<span className="pp-mono">
					mailbox &gt; domain &gt; org &gt; global fallback
				</span>{" "}
				— so configuring a narrower scope routes it away from the wider
				channel rather than notifying both.
			</p>

			<div className="space-y-3" role="radiogroup" aria-label="New mail webhook">
				{option("inherit", "Inherit", INHERIT_COPY[tier])}
				{option(
					"muted",
					"Mute this scope",
					`No notification for ${SCOPE_COPY[tier]} — and no fall-through to a wider channel.`,
				)}
				{option(
					"configured",
					"Send to a webhook",
					"Post to the endpoint held in a named Worker Secret.",
				)}
			</div>

			{mode === "configured" && (
				<div className="border-t border-line mt-4 pt-4 space-y-2">
					<Input
						label="Webhook secret name"
						value={value?.urlSecret ?? ""}
						onChange={(e) => {
							// A result left standing next to an edited draft reads as a
							// pass for a configuration that was never tested.
							setTestResult(null);
							setSecretDraft(e.target.value);
							// Spread, don't replace: a bare literal drops `format`
							// and silently reverts the tier to chat prose.
							onChange({ ...value, enabled: true, urlSecret: e.target.value });
						}}
						placeholder={`${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}SOC`}
						aria-invalid={secretInvalid || undefined}
					/>
					{secretInvalid && (
						<p role="alert" className="text-xs text-red-600 dark:text-red-400">
							Secret name must start with {NEW_EMAIL_WEBHOOK_SECRET_PREFIX}.
						</p>
					)}
					<fieldset className="pt-2">
						<legend className="text-sm text-ink mb-1">Payload format</legend>
						{(
							[
								[
									"chat",
									"Chat message",
									"A one-line {\"text\"} message — what Slack and Google Chat incoming webhooks render.",
								],
								[
									"json",
									"Structured JSON",
									"The event as fields (sender, subject, folder, verdict, url) for a bot or automation to parse.",
								],
							] as const
						).map(([key, title, description]) => (
							<label
								key={key}
								htmlFor={`new-email-webhook-${tier}-format-${key}`}
								className="flex items-start gap-3 cursor-pointer mt-2"
							>
								<input
									id={`new-email-webhook-${tier}-format-${key}`}
									type="radio"
									name={`new-email-webhook-${tier}-format`}
									checked={(value?.format ?? "chat") === key}
									onChange={() => {
										setTestResult(null);
										onChange(
											// Omit the default rather than storing it, so the
											// blob stays minimal under absent-key-inherits.
											key === "chat"
												? { ...value, enabled: true, format: undefined }
												: { ...value, enabled: true, format: key },
										);
									}}
									className="mt-1 h-4 w-4 accent-accent shrink-0"
								/>
								<span className="flex flex-col">
									<span className="text-sm text-ink">{title}</span>
									<span className="text-xs text-ink-3 mt-0.5 max-w-md">
										{description}
									</span>
								</span>
							</label>
						))}
					</fieldset>

					<p className="text-xs text-ink-3">
						Name of the Worker Secret holding the endpoint — set it with{" "}
						<code className="pp-mono">wrangler secret put &lt;name&gt;</code>.
						The endpoint itself is a bearer credential and is never stored in
						settings.
					</p>

					<div className="flex items-center gap-2 border-t border-line pt-3">
						<Button
							variant="secondary"
							size="sm"
							type="button"
							onClick={runTest}
							loading={testing}
							disabled={secretInvalid}
						>
							Send test
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
					<p className="text-xs text-ink-3">
						Sends one clearly-marked test message to the live destination, signed
						the same way real mail is.
					</p>
				</div>
			)}
		</div>
	);
}
