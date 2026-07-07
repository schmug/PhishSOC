// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Badge, Button, Dialog, Input, Loader, Switch } from "@cloudflare/kumo";
import { RobotIcon, ArrowCounterClockwiseIcon } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router";
import { useFeedback } from "~/lib/feedback";
import { useMailbox, useUpdateMailbox } from "~/queries/mailboxes";
import { useOrgSettings } from "~/queries/org-settings";
import { useDomainSettings } from "~/queries/domain-settings";
import { useTextModels } from "~/queries/text-models";
import { SecuritySettingsPanel } from "~/components/SecuritySettingsPanel";
import { AclMembersPanel } from "~/components/AclMembersPanel";
import { PasskeyPanel } from "~/components/PasskeyPanel";
import {
	HubSettingsPanel,
	normalizeHubConfig,
	validateHubConfig,
	type HubFieldErrors,
} from "~/components/HubSettingsPanel";
import { SidecarSettingsCard, type SidecarFormValue } from "~/components/SidecarSettingsCard";
import type { HubConfigSettings, SecuritySettings, YaraMailScannerSettings } from "~/types";
import {
	TEXT_MODELS,
	SECURITY_MODELS,
	DEFAULT_INJECTION_SCANNER_MODEL,
	DEFAULT_DRAFT_VERIFIER_MODEL,
	DEFAULT_CLASSIFIER_MODEL,
} from "shared/mailbox-settings";

// Placeholder shown in the textarea when no custom prompt is set.
// The authoritative default prompt lives in workers/agent/index.ts (DEFAULT_SYSTEM_PROMPT).
const PROMPT_PLACEHOLDER = `You are an email assistant that helps manage this inbox. You read emails, draft replies, and help organize conversations.\n\nWrite like a real person. Short, direct, flowing prose. Plain text only.\n\n(Leave empty to use the full built-in default prompt)`;

interface OrgSettingsShape {
	agentSystemPrompt?: string;
	agentModel?: string;
	autoDraft?: { enabled?: boolean };
	injectionScannerModel?: string;
	draftVerifierModel?: string;
	classifierModel?: string;
	security?: SecuritySettings;
	intel?: { hub?: HubConfigSettings };
}

type DomainSettingsShape = OrgSettingsShape;

/** Domain part of an email address (lowercased). Returns null for
 *  malformed input — the caller treats null as "no domain tier" and the
 *  UI falls back to org/default badges. */
function domainFromMailboxId(mailboxId: string | undefined): string | null {
	if (!mailboxId) return null;
	const at = mailboxId.lastIndexOf("@");
	if (at < 0 || at === mailboxId.length - 1) return null;
	return mailboxId.slice(at + 1).toLowerCase();
}

/** Pill rendered next to a per-mailbox field. The "inherited" variant
 *  shows the *closest* tier that supplied the value — domain wins over
 *  org when both have it, matching the resolver's mailbox > domain > org
 *  > default precedence. Wrapped in a span carrying the data-testid
 *  because Kumo's Badge doesn't forward arbitrary props. */
function InheritanceBadge({
	override,
	source,
}: {
	override: boolean;
	source: "domain" | "org" | null;
	}) {
	if (override) {
		return (
			<span data-testid="override-badge">
				<Badge variant="primary">Override</Badge>
			</span>
		);
	}
	if (source === "domain") {
		return (
			<span data-testid="inherited-domain-badge">
				<Badge variant="secondary">Inherited from domain</Badge>
			</span>
		);
	}
	return (
		<span data-testid="inherited-badge">
			<Badge variant="secondary">Inherited from org</Badge>
		</span>
	);
}

export default function SettingsRoute() {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const feedback = useFeedback();
	const { data: mailbox } = useMailbox(mailboxId);
	const { data: orgData } = useOrgSettings();
	const domainName = domainFromMailboxId(mailboxId);
	const { data: domainData } = useDomainSettings(domainName ?? undefined);
	const updateMailboxMutation = useUpdateMailbox();
	const { models: availableModels } = useTextModels();

	const orgSettings = (orgData?.settings ?? {}) as OrgSettingsShape;
	const domainSettings = (domainData?.settings ?? {}) as DomainSettingsShape;

	// For each inheritable field, decide which tier wins when the mailbox
	// is inheriting. Domain takes precedence over org — matches the
	// resolver's mailbox > domain > org > default chain.
	const sourceFor = (
		field: keyof DomainSettingsShape,
	): "domain" | "org" | null => {
		if (domainSettings[field] !== undefined) return "domain";
		if (orgSettings[field] !== undefined) return "org";
		return null;
	};

	const [displayName, setDisplayName] = useState("");

	// Per-field override flags + values. `override` is true when the
	// mailbox tier supplies its own value (and the save will write it);
	// false when the field inherits the org tier (save omits it so the
	// PUT-side stripDefaultEqual + the resolver's absent-key-inherits
	// semantics keep the inheritance chain alive).
	const [promptOverride, setPromptOverride] = useState(false);
	const [agentPrompt, setAgentPrompt] = useState("");

	const [autoDraftOverride, setAutoDraftOverride] = useState(false);
	const [autoDraftEnabled, setAutoDraftEnabled] = useState(true);

	const [modelOverride, setModelOverride] = useState(false);
	const [modelChoice, setModelChoice] = useState<string>(TEXT_MODELS[0]);
	const [customModel, setCustomModel] = useState("");

	const [injectionScannerOverride, setInjectionScannerOverride] = useState(false);
	const [injectionScannerModelChoice, setInjectionScannerModelChoice] = useState<string>(SECURITY_MODELS[0]);
	const [draftVerifierOverride, setDraftVerifierOverride] = useState(false);
	const [draftVerifierModelChoice, setDraftVerifierModelChoice] = useState<string>(SECURITY_MODELS[0]);
	const [classifierOverride, setClassifierOverride] = useState(false);
	const [classifierModelChoice, setClassifierModelChoice] = useState<string>(SECURITY_MODELS[0]);

	const [pendingSecurityModel, setPendingSecurityModel] = useState<{
		field: "injectionScannerModel" | "draftVerifierModel" | "classifierModel";
		from: string;
		to: string;
	} | null>(null);

	const [securityOverride, setSecurityOverride] = useState(false);
	const [security, setSecurity] = useState<SecuritySettings | undefined>(undefined);

	const [hubOverride, setHubOverride] = useState(false);
	const [hub, setHub] = useState<HubConfigSettings | undefined>(undefined);
	const [hubErrors, setHubErrors] = useState<HubFieldErrors | undefined>(undefined);

	// Attachment scanner (yaramail sidecar, #258 / #256). Off by default —
	// a fresh mailbox never contacts the sidecar unless the operator opts in.
	const [yaraScannerEnabled, setYaraScannerEnabled] = useState(false);
	const [yaraScannerEndpointUrl, setYaraScannerEndpointUrl] = useState("");

	// API-sidecar (Google Workspace polling, #31). null = not configured.
	// `savedConfigExists` gates the observe→active mode toggle: new configs
	// can only start in observe, promotion is a second save.
	const [sidecar, setSidecar] = useState<SidecarFormValue | null>(null);
	const [savedSidecarExists, setSavedSidecarExists] = useState(false);

	const [isSaving, setIsSaving] = useState(false);

	// Initialise form state from the resolved settings ONCE per mailbox.
	// Re-running on every (mailbox, orgData) change clobbers user edits if
	// either query returns a fresh object reference each render — react-query
	// memoises in production, but tests with `vi.mock` typically don't, so a
	// purely dep-based guard is fragile. The ref tracks the mailboxId we
	// initialised against; navigating to a different mailbox forces re-init.
	const initialisedFor = useRef<string | null>(null);

	useEffect(() => {
		if (!mailbox || !mailboxId) return;
		if (initialisedFor.current === mailboxId) return;
		initialisedFor.current = mailboxId;
		const s = mailbox.settings as
			| ({
					autoDraft?: { enabled?: boolean };
					agentModel?: string;
			  } & Record<string, unknown>)
			| undefined;

		setDisplayName(mailbox.settings?.fromName || mailbox.name || "");

		// Inheritance fallback for the "no override" case: domain wins over
		// org, matching the resolver's mailbox > domain > org > default chain.
		// The form displays this fallback as the rendered value so the user
		// sees what's actually in effect for the mailbox right now.

		// Prompt
		const mailboxPrompt = mailbox.settings?.agentSystemPrompt;
		if (mailboxPrompt && mailboxPrompt.trim()) {
			setPromptOverride(true);
			setAgentPrompt(mailboxPrompt);
		} else {
			setPromptOverride(false);
			setAgentPrompt(domainSettings.agentSystemPrompt ?? orgSettings.agentSystemPrompt ?? "");
		}

		// autoDraft
		if (s?.autoDraft) {
			setAutoDraftOverride(true);
			setAutoDraftEnabled(s.autoDraft.enabled ?? true);
		} else {
			setAutoDraftOverride(false);
			setAutoDraftEnabled(
				domainSettings.autoDraft?.enabled ?? orgSettings.autoDraft?.enabled ?? true,
			);
		}

		// agentModel
		const initialModel = s?.agentModel;
		if (initialModel) {
			setModelOverride(true);
			if (availableModels.includes(initialModel)) {
				setModelChoice(initialModel);
				setCustomModel("");
			} else {
				setModelChoice("__custom__");
				setCustomModel(initialModel);
			}
		} else {
			setModelOverride(false);
			const inheritedModel =
				domainSettings.agentModel ??
				orgSettings.agentModel ??
				availableModels[0] ??
				TEXT_MODELS[0];
			if (availableModels.includes(inheritedModel)) {
				setModelChoice(inheritedModel);
				setCustomModel("");
			} else {
				setModelChoice("__custom__");
				setCustomModel(inheritedModel);
			}
		}

		// security model overrides (#151 PR A): mailbox > org > default.
		// Domain tier intentionally excluded — same risk without UI guardrails.
		const rawSettings = mailbox.settings as Record<string, unknown> | undefined;
		const mailboxISM = rawSettings?.injectionScannerModel as string | undefined;
		const mailboxDVM = rawSettings?.draftVerifierModel as string | undefined;
		const mailboxCM = rawSettings?.classifierModel as string | undefined;

		if (mailboxISM) {
			setInjectionScannerOverride(true);
			setInjectionScannerModelChoice(mailboxISM);
		} else {
			setInjectionScannerOverride(false);
			setInjectionScannerModelChoice(
				orgSettings.injectionScannerModel ?? DEFAULT_INJECTION_SCANNER_MODEL,
			);
		}
		if (mailboxDVM) {
			setDraftVerifierOverride(true);
			setDraftVerifierModelChoice(mailboxDVM);
		} else {
			setDraftVerifierOverride(false);
			setDraftVerifierModelChoice(
				orgSettings.draftVerifierModel ?? DEFAULT_DRAFT_VERIFIER_MODEL,
			);
		}
		if (mailboxCM) {
			setClassifierOverride(true);
			setClassifierModelChoice(mailboxCM);
		} else {
			setClassifierOverride(false);
			setClassifierModelChoice(
				orgSettings.classifierModel ?? DEFAULT_CLASSIFIER_MODEL,
			);
		}

		// security: domain block wins over org block when the mailbox doesn't
		// override. Whole-object semantics — never deep-merged.
		if (mailbox.settings?.security) {
			setSecurityOverride(true);
			setSecurity(mailbox.settings.security);
		} else {
			setSecurityOverride(false);
			setSecurity(domainSettings.security ?? orgSettings.security);
		}

		// intel.hub
		if (mailbox.settings?.intel?.hub) {
			setHubOverride(true);
			setHub(mailbox.settings.intel.hub);
		} else {
			setHubOverride(false);
			setHub(domainSettings.intel?.hub ?? orgSettings.intel?.hub);
		}
		setHubErrors(undefined);

		// yaramail_scanner — off by default; never pre-populate endpoint URL
		// unless the mailbox has an explicit saved config with enabled: true.
		const savedYara = (mailbox.settings as Record<string, unknown> | undefined)
			?.yaramail_scanner as YaraMailScannerSettings | undefined;
		if (savedYara?.enabled) {
			setYaraScannerEnabled(true);
			setYaraScannerEndpointUrl(savedYara.endpoint_url ?? "");
		} else {
			setYaraScannerEnabled(false);
			setYaraScannerEndpointUrl("");
		}

		// sidecar (#31) — strictly per-mailbox, no inheritance. Normalize
		// absent optional fields to the card's defaults when a partial block
		// is present (e.g. saved before `mode` existed).
		const savedSidecar = (mailbox.settings as { sidecar?: SidecarFormValue } | undefined)?.sidecar;
		setSavedSidecarExists(!!savedSidecar);
		setSidecar(
			savedSidecar
				? {
						provider: "workspace",
						credentials_secret_name: savedSidecar.credentials_secret_name,
						mode: savedSidecar.mode ?? "observe",
						quarantine_behavior: savedSidecar.quarantine_behavior ?? "label-only",
						retention_days: savedSidecar.retention_days ?? 7,
					}
				: null,
		);

		// availableModels intentionally omitted from deps — see commit
		// message for the rationale (re-running this effect would clobber
		// edits when the dynamic models list resolves).
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [mailbox, orgData, domainData, mailboxId]);

	const handleSave = async () => {
		if (!mailbox || !mailboxId) return;

		const resolvedModel = modelChoice === "__custom__" ? customModel.trim() : modelChoice;
		if (modelOverride && modelChoice === "__custom__" && !resolvedModel) {
			feedback.error("Custom model cannot be empty");
			return;
		}
		if (modelOverride && resolvedModel && !resolvedModel.startsWith("@cf/")) {
			feedback.error("Model must start with @cf/");
			return;
		}

		// Hub validation runs only when override is on; if the mailbox
		// is inheriting, we don't write any intel.hub key and the worker
		// resolver picks up the org-level config instead.
		let nextIntel: { hub?: HubConfigSettings } | undefined;
		if (hubOverride) {
			const hubValidation = validateHubConfig(hub);
			setHubErrors(hubValidation ?? undefined);
			if (hubValidation) {
				feedback.error("Fix the threat-intel hub fields before saving.");
				return;
			}
			const normalizedHub = normalizeHubConfig(hub);
			if (normalizedHub) {
				const existingIntel = mailbox.settings?.intel ?? {};
				nextIntel = { ...existingIntel, hub: normalizedHub };
			}
		} else {
			// Preserve any other intel.* keys (#29 peer subscriptions, etc.)
			// while explicitly removing the hub override.
			const existingIntel = { ...(mailbox.settings?.intel ?? {}) };
			delete existingIntel.hub;
			nextIntel = Object.keys(existingIntel).length > 0 ? existingIntel : undefined;
		}

		setIsSaving(true);
		// Build the PUT payload. Per audit Q5/Q6/Q8: undefined fields get
		// stripped server-side via stripDefaultEqual (PR1) so the resolver
		// can fall through to the org tier on the next read.
		// yaramail_scanner: include only when enabled; absent key strips via
		// stripDefaultEqual on the server, consistent with absent-key semantics.
		const nextYaraScanner: YaraMailScannerSettings | undefined = yaraScannerEnabled
			? { enabled: true, endpoint_url: yaraScannerEndpointUrl.trim() || undefined }
			: undefined;

		const settings = {
			...mailbox.settings,
			fromName: displayName,
			agentSystemPrompt: promptOverride ? agentPrompt.trim() || undefined : undefined,
			autoDraft: autoDraftOverride ? { enabled: autoDraftEnabled } : undefined,
			agentModel: modelOverride ? resolvedModel || undefined : undefined,
			injectionScannerModel: injectionScannerOverride ? injectionScannerModelChoice : undefined,
			draftVerifierModel: draftVerifierOverride ? draftVerifierModelChoice : undefined,
			classifierModel: classifierOverride ? classifierModelChoice : undefined,
			security: securityOverride ? security : undefined,
			intel: nextIntel,
			yaramail_scanner: nextYaraScanner,
			...(sidecar ? { sidecar } : {}),
		};
		if (!sidecar) delete (settings as Record<string, unknown>).sidecar;
		try {
			await updateMailboxMutation.mutateAsync({ mailboxId, settings });
			feedback.success("Settings saved!");
		} catch {
			feedback.error("Failed to save settings");
		} finally {
			setIsSaving(false);
		}
	};

	// Reset handlers fall back to domain → org → default, matching the
	// resolver chain. Domain wins over org when both have the field.
	const resetPrompt = () => {
		setPromptOverride(false);
		setAgentPrompt(domainSettings.agentSystemPrompt ?? orgSettings.agentSystemPrompt ?? "");
	};
	const resetAutoDraft = () => {
		setAutoDraftOverride(false);
		setAutoDraftEnabled(
			domainSettings.autoDraft?.enabled ?? orgSettings.autoDraft?.enabled ?? true,
		);
	};
	const resetModel = () => {
		setModelOverride(false);
		const inheritedModel =
			domainSettings.agentModel ??
			orgSettings.agentModel ??
			availableModels[0] ??
			TEXT_MODELS[0];
		if (availableModels.includes(inheritedModel)) {
			setModelChoice(inheritedModel);
			setCustomModel("");
		} else {
			setModelChoice("__custom__");
			setCustomModel(inheritedModel);
		}
	};
	const resetSecurity = () => {
		setSecurityOverride(false);
		setSecurity(domainSettings.security ?? orgSettings.security);
	};
	const resetHub = () => {
		setHubOverride(false);
		setHub(domainSettings.intel?.hub ?? orgSettings.intel?.hub);
		setHubErrors(undefined);
	};

	const resetInjectionScannerModel = () => {
		setInjectionScannerOverride(false);
		setInjectionScannerModelChoice(
			orgSettings.injectionScannerModel ?? DEFAULT_INJECTION_SCANNER_MODEL,
		);
	};
	const resetDraftVerifierModel = () => {
		setDraftVerifierOverride(false);
		setDraftVerifierModelChoice(
			orgSettings.draftVerifierModel ?? DEFAULT_DRAFT_VERIFIER_MODEL,
		);
	};
	const resetClassifierModel = () => {
		setClassifierOverride(false);
		setClassifierModelChoice(orgSettings.classifierModel ?? DEFAULT_CLASSIFIER_MODEL);
	};

	// Gate on every tier query — the init useEffect uses all of mailbox,
	// org, and (when applicable) domain to initialise the per-field
	// override flags. Rendering the form before any tier resolves lets the
	// user start editing too early; the useRef "initialised once per
	// mailboxId" guard prevents re-runs from clobbering edits, but the
	// loader gate makes sure the FIRST render already has every tier.
	if (!mailbox || !orgData || (domainName && !domainData)) {
		return (
			<div className="flex justify-center py-20">
				<Loader size="lg" />
			</div>
		);
	}

	return (
		<div className="max-w-2xl px-4 py-4 md:px-8 md:py-6 h-full overflow-y-auto">
			<h1 className="pp-serif text-ink mb-2">Settings</h1>
			<p className="text-xs text-ink-3 mb-6">
				Per-mailbox overrides. Fields marked{" "}
				<Badge variant="secondary">Inherited from domain</Badge> or{" "}
				<Badge variant="secondary">Inherited from org</Badge> use the closest
				tier above — manage those at{" "}
				{domainName ? (
					<>
						<Link to={`/domains/${domainName}/settings`} className="underline">
							/domains/{domainName}/settings
						</Link>
						{" "}or{" "}
					</>
				) : null}
				<Link to="/settings" className="underline">/settings</Link>.
				Editing a field here promotes it to an override that wins for this
				mailbox. Security and <code>intel.hub</code> overrides replace the
				entire upstream block whole (no deep-merge across tiers) — with one
				carve-out: <code>allowlist_senders</code> and{" "}
				<code>allowlist_domains</code> extend the org allowlists rather than
				replacing them (deduped, lowercased, org entries first) so a
				per-mailbox entry adds to the org list instead of shadowing it.
			</p>

			<div className="space-y-6">
				{/* Account — strictly per-mailbox, no inheritance. */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-4">Account</div>
					<div className="space-y-3">
						<Input
							label="Display Name"
							value={displayName}
							onChange={(e) => setDisplayName(e.target.value)}
						/>
						<Input label="Email" type="email" value={mailbox.email} disabled />
					</div>
				</div>

				{/* Passkeys — per-user step-up for risky sends (#376). */}
				<PasskeyPanel />

				{/* Agent System Prompt */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-4">
						<div className="flex items-center gap-2">
							<RobotIcon size={16} weight="duotone" className="text-ink-3" />
							<span className="text-sm font-medium text-ink">AI Agent Prompt</span>
							<InheritanceBadge override={promptOverride} source={sourceFor("agentSystemPrompt")} />
						</div>
						{promptOverride && (
							<Button
								variant="ghost"
								size="xs"
								icon={<ArrowCounterClockwiseIcon size={14} />}
								onClick={resetPrompt}
								data-testid="reset-prompt"
							>
								Reset to inherited
							</Button>
						)}
					</div>
					<p className="text-xs text-ink-3 mb-3">
						{promptOverride
							? "This mailbox uses a custom prompt — overrides the inherited value."
							: `Inheriting the ${sourceFor("agentSystemPrompt") === "domain" ? "domain" : "org"} prompt. Type below to create an override.`}
					</p>
					<textarea
						value={agentPrompt}
						onChange={(e) => {
							setAgentPrompt(e.target.value);
							setPromptOverride(true);
						}}
						placeholder={PROMPT_PLACEHOLDER}
						rows={12}
						className="w-full resize-y rounded-lg border border-line bg-paper-2 px-3 py-2 text-xs text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent font-mono leading-relaxed"
					/>
				</div>

				{/* Behavior */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-4">
						<div className="flex items-center gap-2">
							<span className="text-sm font-medium text-ink">Behavior</span>
						</div>
					</div>

					<label className="flex items-start justify-between gap-3 mb-5">
						<span className="flex flex-col">
							<span className="flex items-center gap-2 text-sm text-ink">
								Auto-draft replies
								<InheritanceBadge override={autoDraftOverride} source={sourceFor("autoDraft")} />
								{autoDraftOverride && (
									<button
										type="button"
										onClick={resetAutoDraft}
										className="text-xs text-ink-3 underline hover:text-ink"
										data-testid="reset-autodraft"
									>
										Reset
									</button>
								)}
							</span>
							<span className="text-xs text-ink-3 mt-1 max-w-md">
								Generate a draft reply automatically when new mail arrives.
								Drafts are never sent without explicit confirmation.
							</span>
						</span>
						<input
							type="checkbox"
							checked={autoDraftEnabled}
							onChange={(e) => {
								setAutoDraftEnabled(e.target.checked);
								setAutoDraftOverride(true);
							}}
							className="mt-1 h-4 w-4 accent-accent shrink-0"
							aria-label="Auto-draft replies"
						/>
					</label>

					<div>
						<div className="flex items-center justify-between mb-1.5">
							<label htmlFor="agent-model-select" className="block text-sm text-ink">
								<span className="inline-flex items-center gap-2">
									Agent model
									<InheritanceBadge override={modelOverride} source={sourceFor("agentModel")} />
								</span>
							</label>
							{modelOverride && (
								<button
									type="button"
									onClick={resetModel}
									className="text-xs text-ink-3 underline hover:text-ink"
									data-testid="reset-model"
								>
									Reset to inherited
								</button>
							)}
						</div>
						<select
							id="agent-model-select"
							value={modelChoice}
							onChange={(e) => {
								setModelChoice(e.target.value);
								setModelOverride(true);
							}}
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
								onChange={(e) => {
									setCustomModel(e.target.value);
									setModelOverride(true);
								}}
								className="mt-2 w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent"
							/>
						)}
						<p className="text-xs text-ink-3 mt-2">
							Used for chat and auto-draft. Custom values must start with{" "}
							<code className="pp-mono">@cf/</code>.
						</p>
					</div>
				</div>

				{/* Detection models — per-mailbox override for the three security
				    AI surfaces (#151 PR A). Chain is mailbox > org > default;
				    domain tier excluded (same risk without UI guardrails). */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-2">Detection models</div>
					<p className="text-xs text-ink-3 mb-4">
						Override the AI models the security pipeline uses for this mailbox.
						Inherits from the org when not set. Only pre-vetted models are
						offered — switching to an untested model can significantly degrade
						detection accuracy. A confirmation is required for every override.
					</p>
					<SecurityModelDropdown
						label="Prompt-injection scanner"
						description="Checks incoming mail for prompt-injection attempts before routing to the agent."
						fieldName="injectionScannerModel"
						override={injectionScannerOverride}
						value={injectionScannerModelChoice}
						orgValue={orgSettings.injectionScannerModel ?? DEFAULT_INJECTION_SCANNER_MODEL}
						onChange={(to) => {
							const from = injectionScannerOverride
								? injectionScannerModelChoice
								: (orgSettings.injectionScannerModel ?? DEFAULT_INJECTION_SCANNER_MODEL);
							if (to !== from) setPendingSecurityModel({ field: "injectionScannerModel", from, to });
						}}
						onReset={resetInjectionScannerModel}
					/>
					<SecurityModelDropdown
						label="Draft verifier"
						description="Reviews auto-drafted replies for accuracy and safety before surfacing them."
						fieldName="draftVerifierModel"
						override={draftVerifierOverride}
						value={draftVerifierModelChoice}
						orgValue={orgSettings.draftVerifierModel ?? DEFAULT_DRAFT_VERIFIER_MODEL}
						onChange={(to) => {
							const from = draftVerifierOverride
								? draftVerifierModelChoice
								: (orgSettings.draftVerifierModel ?? DEFAULT_DRAFT_VERIFIER_MODEL);
							if (to !== from) setPendingSecurityModel({ field: "draftVerifierModel", from, to });
						}}
						onReset={resetDraftVerifierModel}
					/>
					<SecurityModelDropdown
						label="Classifier"
						description="Classifies incoming mail as safe / spam / phishing / BEC / suspicious."
						fieldName="classifierModel"
						override={classifierOverride}
						value={classifierModelChoice}
						orgValue={orgSettings.classifierModel ?? DEFAULT_CLASSIFIER_MODEL}
						onChange={(to) => {
							const from = classifierOverride
								? classifierModelChoice
								: (orgSettings.classifierModel ?? DEFAULT_CLASSIFIER_MODEL);
							if (to !== from) setPendingSecurityModel({ field: "classifierModel", from, to });
						}}
						onReset={resetClassifierModel}
					/>
				</div>

				{/* Confirmation dialog for security model overrides */}
				<Dialog.Root
					open={pendingSecurityModel !== null}
					onOpenChange={(open) => { if (!open) setPendingSecurityModel(null); }}
				>
					<Dialog size="sm" className="p-6">
						<Dialog.Title className="text-base font-semibold mb-2">
							Override detection model?
						</Dialog.Title>
						{pendingSecurityModel && (
							<Dialog.Description className="text-sm text-ink-3 mb-4 space-y-2">
								<p>
									Switching from{" "}
									<code className="text-ink">{pendingSecurityModel.from}</code> to{" "}
									<code className="text-ink">{pendingSecurityModel.to}</code> for this mailbox.
									This affects detection.
								</p>
								{pendingSecurityModel.field === "injectionScannerModel" && (
									<p className="font-medium text-amber-700 dark:text-amber-400">
										This is a security-critical model. Operators have downgraded detection
										by 60%+ when overriding without testing.
									</p>
								)}
							</Dialog.Description>
						)}
						<div className="flex justify-end gap-2">
							<Dialog.Close
								render={(props) => (
									<Button {...props} variant="secondary" size="sm" type="button">
										Cancel
									</Button>
								)}
							/>
							<Button
								variant="primary"
								size="sm"
								onClick={() => {
									if (!pendingSecurityModel) return;
									const { field, to } = pendingSecurityModel;
									if (field === "injectionScannerModel") {
										setInjectionScannerModelChoice(to);
										setInjectionScannerOverride(true);
									} else if (field === "draftVerifierModel") {
										setDraftVerifierModelChoice(to);
										setDraftVerifierOverride(true);
									} else {
										setClassifierModelChoice(to);
										setClassifierOverride(true);
									}
									setPendingSecurityModel(null);
								}}
							>
								Override
							</Button>
						</div>
					</Dialog>
				</Dialog.Root>

				{/* Security — block-level inheritance. Override carries the WHOLE
				    security object (incl. allowlists). v1 has no extend-merge for
				    arrays; tracked as #149. */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-3">
						<span className="text-sm font-medium text-ink inline-flex items-center gap-2">
							Security
							<InheritanceBadge override={securityOverride} source={sourceFor("security")} />
						</span>
						{securityOverride && (
							<button
								type="button"
								onClick={resetSecurity}
								className="text-xs text-ink-3 underline hover:text-ink"
								data-testid="reset-security"
							>
								Reset to inherited
							</button>
						)}
					</div>
					{!securityOverride && (
						<div className="rounded-md border border-line bg-paper-2 px-3 py-2 mb-3 text-xs text-ink-3">
							Inheriting the {sourceFor("security") === "domain" ? "domain" : "org-wide"} security
							block. Editing below promotes this mailbox to an override that{" "}
							<strong>replaces the entire upstream security block</strong> —
							including allowlists, thresholds, and trusted authserv-ids.
							Cross-tier extend-merge for allowlist arrays is tracked as a
							follow-up.
						</div>
					)}
					<SecuritySettingsPanel
						value={security}
						onChange={(next) => {
							setSecurity(next);
							setSecurityOverride(true);
						}}
					/>
				</div>

				{/* Threat-intel hub (#97) — block-level inheritance. */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-3">
						<span className="text-sm font-medium text-ink inline-flex items-center gap-2">
							Threat-intel hub
							<InheritanceBadge
								override={hubOverride}
								source={
									domainSettings.intel?.hub !== undefined
										? "domain"
										: orgSettings.intel?.hub !== undefined
											? "org"
											: null
								}
							/>
						</span>
						{hubOverride && (
							<button
								type="button"
								onClick={resetHub}
								className="text-xs text-ink-3 underline hover:text-ink"
								data-testid="reset-hub"
							>
								Reset to inherited
							</button>
						)}
					</div>
					{!hubOverride && (
						<div className="rounded-md border border-line bg-paper-2 px-3 py-2 mb-3 text-xs text-ink-3">
							Inheriting the {sourceFor("intel") === "domain" ? "domain" : "org-wide"} hub config.
							Editing below creates a per-mailbox hub that replaces the
							upstream config whole.
						</div>
					)}
					<HubSettingsPanel
						value={hub}
						onChange={(next) => {
							setHub(next);
							setHubOverride(true);
							if (hubErrors) setHubErrors(validateHubConfig(next) ?? undefined);
						}}
						errors={hubErrors}
					/>
				</div>

				{/* Attachment scanner (yaramail sidecar, #258 / #256) */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-2">Attachment scanner</div>
					<p className="text-xs text-ink-3 mb-4">
						Optional async attachment-scanning sidecar (yaramail). When enabled,
						attachments are forwarded to the configured sidecar endpoint for
						deep content inspection. Disabled by default — only enable when you
						have a sidecar container deployed and the endpoint URL ready.
					</p>
					<div className="space-y-3">
						<Switch
							label="Enable attachment scanner"
							checked={yaraScannerEnabled}
							onCheckedChange={(v) => {
								setYaraScannerEnabled(v);
								if (!v) setYaraScannerEndpointUrl("");
							}}
							data-testid="yaramail-scanner-toggle"
						/>
						{yaraScannerEnabled && (
							<div className="border-t border-line pt-4">
								<Input
									label="Sidecar endpoint URL"
									type="url"
									placeholder="https://yaramail.internal/scan"
									value={yaraScannerEndpointUrl}
									onChange={(e) => setYaraScannerEndpointUrl(e.target.value)}
								/>
								<p className="text-xs text-ink-3 mt-2">
									URL of the yaramail sidecar container's HTTP scan endpoint.
									Must be reachable from the Worker runtime. No format validation
									beyond <code className="pp-mono">type="url"</code> — the server
									validates on save.
								</p>
							</div>
						)}
					</div>
				</div>

				{/* API sidecar (Google Workspace polling, #31) */}
				<SidecarSettingsCard
					value={sidecar}
					onChange={setSidecar}
					health={mailbox.sidecar_health ?? null}
					savedConfigExists={savedSidecarExists}
					mailboxId={mailboxId!}
				/>

				{/* Access / Members — per-mailbox ACL panel (#291). Not part of the
				    settings-tier save; managed via separate ACL endpoints. */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-4">Access</div>
					<p className="text-xs text-ink-3 mb-4">
						Manage who can access this mailbox. Lock it down to restrict access to
						specific members; unscoped mailboxes are visible to everyone admitted
						by Cloudflare Access.
					</p>
					<AclMembersPanel mailboxId={mailboxId!} />
				</div>

				{/* Save */}
				<div className="flex justify-end">
					<Button variant="primary" onClick={handleSave} loading={isSaving}>
						Save Changes
					</Button>
				</div>
			</div>
		</div>
	);
}

interface SecurityModelDropdownProps {
	label: string;
	description: string;
	fieldName: string;
	override: boolean;
	value: string;
	orgValue: string;
	onChange: (to: string) => void;
	onReset: () => void;
}

function SecurityModelDropdown({
	label,
	description,
	fieldName,
	override,
	value,
	orgValue,
	onChange,
	onReset,
}: SecurityModelDropdownProps) {
	const displayValue = override ? value : orgValue;
	return (
		<div className="mb-4">
			<div className="flex items-center justify-between mb-1">
				<label htmlFor={`${fieldName}-select`} className="text-sm text-ink">
					<span className="inline-flex items-center gap-2">
						{label}
						{override ? (
							<span data-testid={`override-badge-${fieldName}`}>
								<Badge variant="primary">Override</Badge>
							</span>
						) : (
							<span data-testid={`inherited-badge-${fieldName}`}>
								<Badge variant="secondary">Inherited from org</Badge>
							</span>
						)}
					</span>
				</label>
				{override && (
					<button
						type="button"
						onClick={onReset}
						className="text-xs text-ink-3 underline hover:text-ink"
						data-testid={`reset-${fieldName}`}
					>
						Reset to inherited
					</button>
				)}
			</div>
			<p className="text-xs text-ink-3 mb-2">{description}</p>
			<select
				id={`${fieldName}-select`}
				value={displayValue}
				onChange={(e) => onChange(e.target.value)}
				className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-accent"
			>
				{SECURITY_MODELS.map((m) => (
					<option key={m} value={m}>{m}</option>
				))}
			</select>
		</div>
	);
}
