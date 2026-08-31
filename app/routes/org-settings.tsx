// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Badge, Button, Loader } from "@cloudflare/kumo";
import { RobotIcon, ArrowCounterClockwiseIcon } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { useFeedback } from "~/lib/feedback";
import { useOrgSettings, useUpdateOrgSettings } from "~/queries/org-settings";
import { useTextModels } from "~/queries/text-models";
import { SecuritySettingsPanel } from "~/components/SecuritySettingsPanel";
import {
	HubSettingsPanel,
	normalizeHubConfig,
	validateHubConfig,
	type HubFieldErrors,
} from "~/components/HubSettingsPanel";
import Shell from "~/components/phishsoc/Shell";
import type { HubConfigSettings, SecuritySettings } from "~/types";
import {
	DEFAULT_CLASSIFIER_MODEL,
	DEFAULT_DRAFT_VERIFIER_MODEL,
	DEFAULT_INJECTION_SCANNER_MODEL,
	NEW_EMAIL_WEBHOOK_SECRET_PREFIX,
	TEXT_MODELS,
} from "shared/mailbox-settings";
import type { NewEmailWebhookSettings } from "shared/mailbox-settings";
import {
	NewEmailWebhookCard,
	isNewEmailWebhookValid,
} from "~/components/NewEmailWebhookCard";

const PROMPT_PLACEHOLDER = `You are an email assistant that helps manage this inbox. You read emails, draft replies, and help organize conversations.\n\nWrite like a real person. Short, direct, flowing prose. Plain text only.\n\n(Leave empty to use the full built-in default prompt)`;

interface OrgSettingsShape {
	agentSystemPrompt?: string;
	agentModel?: string;
	autoDraft?: { enabled?: boolean };
	injectionScannerModel?: string;
	draftVerifierModel?: string;
	classifierModel?: string;
	security?: SecuritySettings;
	intel?: { hub?: HubConfigSettings; feeds?: unknown[] };
	/** Written via POST /api/v1/org/domains — not edited on this page. */
	domains?: string[];
	gateway?: { arcSealerDomain?: string; arcSelector?: string };
	newEmailWebhook?: NewEmailWebhookSettings;
}

/**
 * Org-wide settings page (#106). Top-level route at `/settings` — distinct
 * from `/mailbox/:mailboxId/settings`, which now renders override-only state
 * with "Inherited from org" badges per field.
 *
 * Field absence = inherit from system default. The PUT validates through
 * the OrgSettings Zod schema and invalidates the resolver's module-scope
 * ETag cache, so a save propagates to every mailbox's resolved view on the
 * next read.
 */
export default function OrgSettingsRoute() {
	const feedback = useFeedback();
	const { data, isLoading } = useOrgSettings();
	const updateOrg = useUpdateOrgSettings();
	const { models: availableModels } = useTextModels();

	const [agentPrompt, setAgentPrompt] = useState("");
	const [security, setSecurity] = useState<SecuritySettings | undefined>(undefined);
	const [hub, setHub] = useState<HubConfigSettings | undefined>(undefined);
	const [hubErrors, setHubErrors] = useState<HubFieldErrors | undefined>(undefined);
	const [autoDraftEnabled, setAutoDraftEnabled] = useState(true);
	const [modelChoice, setModelChoice] = useState<string>(TEXT_MODELS[0]);
	const [customModel, setCustomModel] = useState("");
	const [injectionScannerModel, setInjectionScannerModel] = useState("");
	const [draftVerifierModel, setDraftVerifierModel] = useState("");
	const [classifierModel, setClassifierModel] = useState("");
	const [arcSealerDomain, setArcSealerDomain] = useState("");
	const [arcSelector, setArcSelector] = useState("");
	// New-mail webhook (#694). undefined = inherit (key omitted on save),
	// {enabled:false} = muted, {enabled:true, urlSecret} = configured.
	const [newEmailWebhook, setNewEmailWebhook] = useState<
		NewEmailWebhookSettings | undefined
	>(undefined);
	const [isSaving, setIsSaving] = useState(false);

	useEffect(() => {
		if (!data?.settings) return;
		const s = data.settings as OrgSettingsShape;
		setAgentPrompt(s.agentSystemPrompt ?? "");
		setSecurity(s.security);
		setHub(s.intel?.hub);
		setHubErrors(undefined);
		setAutoDraftEnabled(s.autoDraft?.enabled === undefined ? true : s.autoDraft.enabled);

		const m = s.agentModel ?? availableModels[0] ?? TEXT_MODELS[0];
		if (availableModels.includes(m)) {
			setModelChoice(m);
			setCustomModel("");
		} else {
			setModelChoice("__custom__");
			setCustomModel(m);
		}

		setInjectionScannerModel(s.injectionScannerModel ?? "");
		setDraftVerifierModel(s.draftVerifierModel ?? "");
		setClassifierModel(s.classifierModel ?? "");
		setArcSealerDomain(s.gateway?.arcSealerDomain ?? "");
		setArcSelector(s.gateway?.arcSelector ?? "");
		// Absent key is the meaningful "inherit" state — load it through as-is.
		setNewEmailWebhook(s.newEmailWebhook);
		// availableModels intentionally omitted from deps — see settings.tsx
		// for the rationale (re-running this effect would clobber edits).
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [data]);

	const handleSave = async () => {
		const resolvedModel = modelChoice === "__custom__" ? customModel.trim() : modelChoice;
		if (modelChoice === "__custom__" && !resolvedModel) {
			feedback.error("Custom model cannot be empty");
			return;
		}
		if (resolvedModel && !resolvedModel.startsWith("@cf/")) {
			feedback.error("Model must start with @cf/");
			return;
		}

		const advancedModelInputs: Array<{ label: string; value: string }> = [
			{ label: "Injection scanner", value: injectionScannerModel.trim() },
			{ label: "Draft verifier", value: draftVerifierModel.trim() },
			{ label: "Classifier", value: classifierModel.trim() },
		];
		for (const m of advancedModelInputs) {
			if (m.value && !m.value.startsWith("@cf/")) {
				feedback.error(`${m.label} model must start with @cf/`);
				return;
			}
		}

		const hubValidation = validateHubConfig(hub);
		setHubErrors(hubValidation ?? undefined);
		if (hubValidation) {
			feedback.error("Fix the threat-intel hub fields before saving.");
			return;
		}

		if (!isNewEmailWebhookValid(newEmailWebhook)) {
			feedback.error(
				`Webhook secret name must start with ${NEW_EMAIL_WEBHOOK_SECRET_PREFIX}`,
			);
			return;
		}

		const existing = (data?.settings ?? {}) as OrgSettingsShape;
		const normalizedHub = normalizeHubConfig(hub);

		// Org PUT is full-replace — spread the persisted blob and only touch
		// fields this page edits. `domains` (POST /api/v1/org/domains) and
		// `intel.feeds` (no org UI yet) must survive an unrelated save.
		let nextIntel: OrgSettingsShape["intel"];
		if (normalizedHub) {
			nextIntel = { ...(existing.intel ?? {}), hub: normalizedHub };
		} else {
			const { hub: _hub, ...rest } = existing.intel ?? {};
			nextIntel = Object.keys(rest).length > 0 ? rest : undefined;
		}

		// Build the org PUT payload. Fields the user left blank/default are
		// sent as undefined so the worker's PUT validator + the resolver's
		// "absent = inherit" semantics produce a clean inheritance chain
		// for every mailbox's resolved view.
		const settings: OrgSettingsShape = {
			...existing,
			agentSystemPrompt: agentPrompt.trim() || undefined,
			autoDraft: { enabled: autoDraftEnabled },
			agentModel: resolvedModel || undefined,
			security,
			intel: nextIntel,
			injectionScannerModel: injectionScannerModel.trim() || undefined,
			draftVerifierModel: draftVerifierModel.trim() || undefined,
			classifierModel: classifierModel.trim() || undefined,
			gateway: (arcSealerDomain.trim() || arcSelector.trim())
				? {
						...(arcSealerDomain.trim() ? { arcSealerDomain: arcSealerDomain.trim() } : {}),
						...(arcSelector.trim() ? { arcSelector: arcSelector.trim() } : {}),
					}
				: {},
		};

		// Inherit is expressed by omitting the key entirely; `...existing`
		// above would otherwise carry a stale block through. A mute
		// (`{enabled:false}`) is written, and stripDefaultEqual keeps it.
		if (newEmailWebhook) {
			settings.newEmailWebhook = newEmailWebhook;
		} else {
			delete settings.newEmailWebhook;
		}

		setIsSaving(true);
		try {
			await updateOrg.mutateAsync(settings);
			feedback.success("Org settings saved!");
		} catch {
			feedback.error("Failed to save org settings");
		} finally {
			setIsSaving(false);
		}
	};

	if (isLoading) {
		return (
			<Shell>
				<div className="flex justify-center py-20">
					<Loader size="lg" />
				</div>
			</Shell>
		);
	}

	const isCustomPrompt = agentPrompt.trim().length > 0;

	return (
		<Shell>
		<div className="max-w-2xl px-4 py-4 md:px-8 md:py-6 h-full overflow-y-auto">
			<h1 className="pp-serif text-ink mb-2">Organization settings</h1>
			<p className="text-xs text-ink-3 mb-6 max-w-xl">
				These defaults apply to every mailbox unless the mailbox sets its own
				value. Per-mailbox overrides replace the org value for that field
				whole — security, intel hub, and intel feeds are NOT deep-merged
				across tiers.
			</p>

			<div className="space-y-6">
				{/* Agent System Prompt */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-4">
						<div className="flex items-center gap-2">
							<RobotIcon size={16} weight="duotone" className="text-ink-3" />
							<span className="text-sm font-medium text-ink">AI Agent Prompt</span>
							{isCustomPrompt ? (
								<Badge variant="primary">Custom</Badge>
							) : (
								<Badge variant="secondary">Default</Badge>
							)}
						</div>
						{isCustomPrompt && (
							<Button
								variant="ghost"
								size="xs"
								icon={<ArrowCounterClockwiseIcon size={14} />}
								onClick={() => setAgentPrompt("")}
							>
								Reset to default
							</Button>
						)}
					</div>
					<p className="text-xs text-ink-3 mb-3">
						Sets the system message every mailbox uses by default. Mailboxes
						can override per-mailbox.
					</p>
					<textarea
						value={agentPrompt}
						onChange={(e) => setAgentPrompt(e.target.value)}
						placeholder={PROMPT_PLACEHOLDER}
						rows={12}
						className="w-full resize-y rounded-lg border border-line bg-paper-2 px-3 py-2 text-xs text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent font-mono leading-relaxed"
					/>
				</div>

				{/* Behavior */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-4">Behavior</div>

					<label className="flex items-start justify-between gap-3 mb-5">
						<span className="flex flex-col">
							<span className="text-sm text-ink">Auto-draft replies</span>
							<span className="text-xs text-ink-3 mt-1 max-w-md">
								Default for every mailbox. Mailboxes can override.
							</span>
						</span>
						<input
							type="checkbox"
							checked={autoDraftEnabled}
							onChange={(e) => setAutoDraftEnabled(e.target.checked)}
							className="mt-1 h-4 w-4 accent-accent shrink-0"
							aria-label="Auto-draft replies"
						/>
					</label>

					<div>
						<label htmlFor="org-agent-model-select" className="block text-sm text-ink mb-1.5">
							Agent model
						</label>
						<select
							id="org-agent-model-select"
							value={modelChoice}
							onChange={(e) => setModelChoice(e.target.value)}
							className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-accent"
						>
							{availableModels.map((m) => (
								<option key={m} value={m}>{m}</option>
							))}
							<option value="__custom__">Custom…</option>
						</select>
						{modelChoice === "__custom__" && (
							<input
								type="text"
								placeholder="@cf/your/model"
								value={customModel}
								onChange={(e) => setCustomModel(e.target.value)}
								className="mt-2 w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent"
							/>
						)}
						<p className="text-xs text-ink-3 mt-2">
							Used for chat and auto-draft across every mailbox. Custom values
							must start with <code className="pp-mono">@cf/</code>.
						</p>
					</div>
				</div>

				{/* Security model overrides — org-only (audit Q7) */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-3">
						Security model overrides
					</div>
					<p className="text-xs text-ink-3 mb-4 max-w-xl">
						These models drive security-critical paths (prompt-injection
						detection, draft verification, email classification). Per-mailbox
						overrides are intentionally not supported — choosing a weaker
						model can let real injections through, and the safe place to make
						that trade-off is once, here. Leave blank to use the tested
						defaults shown as placeholders.
					</p>
					<div className="space-y-4">
						<div>
							<label htmlFor="org-injection-model" className="block text-xs text-ink mb-1">
								Prompt-injection scanner
							</label>
							<input
								id="org-injection-model"
								type="text"
								placeholder={DEFAULT_INJECTION_SCANNER_MODEL}
								value={injectionScannerModel}
								onChange={(e) => setInjectionScannerModel(e.target.value)}
								className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
							/>
						</div>
						<div>
							<label htmlFor="org-verifier-model" className="block text-xs text-ink mb-1">
								Draft verifier
							</label>
							<input
								id="org-verifier-model"
								type="text"
								placeholder={DEFAULT_DRAFT_VERIFIER_MODEL}
								value={draftVerifierModel}
								onChange={(e) => setDraftVerifierModel(e.target.value)}
								className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
							/>
						</div>
						<div>
							<label htmlFor="org-classifier-model" className="block text-xs text-ink mb-1">
								LLM classifier
							</label>
							<input
								id="org-classifier-model"
								type="text"
								placeholder={DEFAULT_CLASSIFIER_MODEL}
								value={classifierModel}
								onChange={(e) => setClassifierModel(e.target.value)}
								className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
							/>
						</div>
					</div>
				</div>

				{/* Inline gateway ARC sealer identity */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-3">
						Inline gateway ARC sealer
					</div>
					<p className="text-xs text-ink-3 mb-4 max-w-xl">
						Publish the matching public key at{" "}
						<code className="pp-mono">&lt;selector&gt;._domainkey.&lt;sealer domain&gt;</code>{" "}
						and set the <code className="pp-mono">ARC_SEAL_PRIVATE_KEY</code> secret —
						see <code className="pp-mono">docs/gateway-mode.md</code>.
					</p>
					<div className="space-y-4">
						<div>
							<label htmlFor="org-arc-sealer-domain" className="block text-xs text-ink mb-1">
								ARC sealer domain
							</label>
							<input
								id="org-arc-sealer-domain"
								type="text"
								placeholder="gw.example.com"
								value={arcSealerDomain}
								onChange={(e) => setArcSealerDomain(e.target.value)}
								className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
							/>
						</div>
						<div>
							<label htmlFor="org-arc-selector" className="block text-xs text-ink mb-1">
								ARC selector
							</label>
							<input
								id="org-arc-selector"
								type="text"
								placeholder="arc1"
								value={arcSelector}
								onChange={(e) => setArcSelector(e.target.value)}
								className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
							/>
						</div>
					</div>
				</div>

				{/* Security defaults */}
				<SecuritySettingsPanel value={security} onChange={setSecurity} />

				{/* Threat-intel hub */}
				<HubSettingsPanel
					value={hub}
					onChange={(next) => {
						setHub(next);
						if (hubErrors) setHubErrors(validateHubConfig(next) ?? undefined);
					}}
					errors={hubErrors}
				/>

				{/* New mail webhook (#694) */}
				<NewEmailWebhookCard
					value={newEmailWebhook}
					onChange={setNewEmailWebhook}
					tier="org"
				/>

				{/* Save */}
				<div className="flex justify-end">
					<Button variant="primary" onClick={handleSave} loading={isSaving}>
						Save Changes
					</Button>
				</div>
			</div>
		</div>
		</Shell>
	);
}
