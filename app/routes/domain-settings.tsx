// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Badge, Button, Loader } from "@cloudflare/kumo";
import { RobotIcon, ArrowCounterClockwiseIcon } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router";
import Shell from "~/components/phishsoc/Shell";
import { useFeedback } from "~/lib/feedback";
import {
	useDomainSettings,
	useUpdateDomainSettings,
} from "~/queries/domain-settings";
import { useTextModels } from "~/queries/text-models";
import { SecuritySettingsPanel } from "~/components/SecuritySettingsPanel";
import {
	HubSettingsPanel,
	normalizeHubConfig,
	validateHubConfig,
	type HubFieldErrors,
} from "~/components/HubSettingsPanel";
import type { HubConfigSettings, SecuritySettings } from "~/types";
import { TEXT_MODELS } from "shared/mailbox-settings";

const PROMPT_PLACEHOLDER = `(Leave empty to inherit from org-wide /settings)`;

interface DomainSettingsShape {
	agentSystemPrompt?: string;
	agentModel?: string;
	autoDraft?: { enabled?: boolean };
	security?: SecuritySettings;
	intel?: { hub?: HubConfigSettings };
}

/**
 * Domain-level settings page (#142). Sits between mailbox and org in the
 * inheritance hierarchy: mailbox > domain > org > system default.
 *
 * Mirrors the org-settings page minus the three security-critical model
 * fields (those stay org-only — per-tier override of the prompt-injection
 * scanner is the same foot-gun without UI guardrails; tracked as #151).
 */
export default function DomainSettingsRoute() {
	const { domain: rawDomain } = useParams<{ domain: string }>();
	const domain = rawDomain?.toLowerCase();
	const feedback = useFeedback();
	const { data, isLoading } = useDomainSettings(domain);
	const updateDomain = useUpdateDomainSettings(domain);
	const { models: availableModels } = useTextModels();

	const [agentPrompt, setAgentPrompt] = useState("");
	const [security, setSecurity] = useState<SecuritySettings | undefined>(undefined);
	const [hub, setHub] = useState<HubConfigSettings | undefined>(undefined);
	const [hubErrors, setHubErrors] = useState<HubFieldErrors | undefined>(undefined);
	const [autoDraftEnabled, setAutoDraftEnabled] = useState(true);
	const [modelChoice, setModelChoice] = useState<string>(TEXT_MODELS[0]);
	const [customModel, setCustomModel] = useState("");
	const [isSaving, setIsSaving] = useState(false);

	// Initialise once per domain (same useRef pattern as the per-mailbox
	// settings page — protects against query-result identity churn that
	// would otherwise clobber edits on every re-render).
	const initialisedFor = useRef<string | null>(null);
	useEffect(() => {
		if (!data?.settings || !domain) return;
		if (initialisedFor.current === domain) return;
		initialisedFor.current = domain;
		const s = data.settings as DomainSettingsShape;
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
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [data, domain]);

	const handleSave = async () => {
		if (!domain) return;
		const resolvedModel = modelChoice === "__custom__" ? customModel.trim() : modelChoice;
		if (modelChoice === "__custom__" && !resolvedModel) {
			feedback.error("Custom model cannot be empty");
			return;
		}
		if (resolvedModel && !resolvedModel.startsWith("@cf/")) {
			feedback.error("Model must start with @cf/");
			return;
		}

		const hubValidation = validateHubConfig(hub);
		setHubErrors(hubValidation ?? undefined);
		if (hubValidation) {
			feedback.error("Fix the threat-intel hub fields before saving.");
			return;
		}

		const normalizedHub = normalizeHubConfig(hub);
		const intelToPersist = normalizedHub ? { hub: normalizedHub } : undefined;

		const settings: DomainSettingsShape = {
			agentSystemPrompt: agentPrompt.trim() || undefined,
			autoDraft: { enabled: autoDraftEnabled },
			agentModel: resolvedModel || undefined,
			security,
			intel: intelToPersist,
		};

		setIsSaving(true);
		try {
			await updateDomain.mutateAsync(settings);
			feedback.success(`Domain settings saved for ${domain}!`);
		} catch {
			feedback.error("Failed to save domain settings");
		} finally {
			setIsSaving(false);
		}
	};

	if (!domain) {
		return (
			<Shell>
				<div className="px-4 py-4 md:px-8 md:py-6">
					<p className="text-sm text-ink-3">Missing domain in URL.</p>
				</div>
			</Shell>
		);
	}

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
			<h1 className="pp-serif text-ink mb-2">Domain settings — {domain}</h1>
			<p className="text-xs text-ink-3 mb-6 max-w-xl">
				Defaults for every mailbox under <code className="pp-mono">{domain}</code>.
				Inheritance order: mailbox &gt; domain &gt; org &gt; system default. Fields left
				blank inherit from <Link to="/settings" className="underline">org-wide settings</Link>;
				per-mailbox overrides replace the value for that mailbox whole.
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
								<Badge variant="secondary">Inherited from org</Badge>
							)}
						</div>
						{isCustomPrompt && (
							<Button
								variant="ghost"
								size="xs"
								icon={<ArrowCounterClockwiseIcon size={14} />}
								onClick={() => setAgentPrompt("")}
							>
								Reset to inherited
							</Button>
						)}
					</div>
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
								Default for every mailbox under this domain.
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
						<label htmlFor="domain-agent-model-select" className="block text-sm text-ink mb-1.5">
							Agent model
						</label>
						<select
							id="domain-agent-model-select"
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
							Used for chat and auto-draft for every mailbox under this domain.
						</p>
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
