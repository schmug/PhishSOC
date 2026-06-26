// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Badge, Input, Switch } from "@cloudflare/kumo";
import { ShieldIcon } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import type {
	SecuritySettings,
	BusinessHoursSettings,
	VerdictThresholdSettings,
	AttachmentAction,
	AttachmentPolicySettings,
	FolderPolicySettings,
} from "~/types";
import { SYSTEM_FOLDER_IDS, FOLDER_DISPLAY_NAMES } from "shared/folders";

/**
 * Per-mailbox security settings UI. Mirrors `MailboxSecuritySettings` in
 * `workers/security/settings.ts` so the same JSON shape round-trips through
 * R2.
 *
 * Contents are intentionally low-density: each control corresponds to one
 * field on the server-side settings object, and each has a short explanatory
 * blurb because the behavior is far from obvious. Defaults here match the
 * DEFAULT_SECURITY_SETTINGS on the server so an empty form shows the same
 * state you'd get from leaving the section unset entirely.
 */

const DEFAULT_THRESHOLDS: VerdictThresholdSettings = { tag: 30, quarantine: 60, block: 80 };
const DEFAULT_BUSINESS_HOURS: BusinessHoursSettings = {
	timezone: "",
	start_hour: 9,
	end_hour: 18,
	weekdays_only: true,
	boost_on_off_hours: false,
};

// Mirrors `DEFAULT_ATTACHMENT_POLICY` in `workers/security/attachments.ts`.
// Kept here so the form shows the same effective state operators get from
// leaving the section untouched on the server. Update both together.
const DEFAULT_ATTACHMENT_POLICY: Required<
	Pick<AttachmentPolicySettings, "executable_action" | "container_action" | "macro_office_action">
> = {
	executable_action: "block",
	container_action: "score",
	macro_office_action: "score",
};

export interface SecuritySettingsPanelProps {
	value: SecuritySettings | undefined;
	onChange: (next: SecuritySettings) => void;
}

export function SecuritySettingsPanel({ value, onChange }: SecuritySettingsPanelProps) {
	const s = value ?? {};
	const thresholds = s.thresholds ?? DEFAULT_THRESHOLDS;
	const bh = s.business_hours;
	const attachment = s.attachment_policy ?? {};
	const folders = s.folder_policies ?? {};

	const patch = (partial: Partial<SecuritySettings>) => onChange({ ...s, ...partial });
	const patchAttachment = (partial: Partial<AttachmentPolicySettings>) =>
		patch({ attachment_policy: { ...attachment, ...partial } });
	const patchFolder = (folderId: string, next: FolderPolicySettings | undefined) => {
		const nextFolders = { ...folders };
		if (!next || (next.mode === undefined && !next.treat_as_verified)) {
			delete nextFolders[folderId];
		} else {
			nextFolders[folderId] = next;
		}
		patch({ folder_policies: nextFolders });
	};

	return (
		<div className="pp-card p-5 space-y-5">
			<div className="flex items-center gap-2">
				<ShieldIcon size={16} weight="duotone" className="text-ink-3" />
				<span className="text-sm font-medium text-ink">Security</span>
				{s.enabled ? (
					s.learning_mode
						? <Badge variant="secondary">Learning</Badge>
						: <Badge variant="primary">Active</Badge>
				) : <Badge variant="secondary">Disabled</Badge>}
			</div>

			<div className="space-y-3">
				<Switch
					label="Enable security pipeline"
					checked={!!s.enabled}
					onCheckedChange={(v) => patch({ enabled: v })}
				/>
				<p className="text-xs text-ink-3 -mt-2">
					Runs SPF/DKIM/DMARC parse, URL heuristics, and an LLM classifier on incoming mail.
					Disabled by default so existing mailboxes aren't affected until you opt in.
				</p>

				<Switch
					label="Learning mode (tag only, never quarantine)"
					checked={!!s.learning_mode}
					onCheckedChange={(v) => patch({ learning_mode: v })}
					disabled={!s.enabled}
				/>
				<p className="text-xs text-ink-3 -mt-2">
					Safe way to dial-in thresholds: verdicts still compute but are capped at "tag".
					Use this for a week before flipping off to audit false-positive rate.
				</p>
			</div>

			{/* Thresholds */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-2">Score thresholds</div>
				<p className="text-xs text-ink-3 mb-3">
					Score 0–100 aggregated from auth, URL, classifier, and reputation signals.
					Values below take effect when the pipeline is enabled.
				</p>
				<div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
					<Input
						label="Tag"
						type="number"
						min={0}
						max={100}
						value={String(thresholds.tag)}
						onChange={(e) => patch({ thresholds: { ...thresholds, tag: clampScore(e.target.value, DEFAULT_THRESHOLDS.tag) } })}
						disabled={!s.enabled}
					/>
					<Input
						label="Quarantine"
						type="number"
						min={0}
						max={100}
						value={String(thresholds.quarantine)}
						onChange={(e) => patch({ thresholds: { ...thresholds, quarantine: clampScore(e.target.value, DEFAULT_THRESHOLDS.quarantine) } })}
						disabled={!s.enabled}
					/>
					<Input
						label="Block"
						type="number"
						min={0}
						max={100}
						value={String(thresholds.block)}
						onChange={(e) => patch({ thresholds: { ...thresholds, block: clampScore(e.target.value, DEFAULT_THRESHOLDS.block) } })}
						disabled={!s.enabled}
					/>
				</div>
			</div>

			{/* Authentication-Results trust */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-2">Trusted authentication servers</div>
				<p className="text-xs text-ink-3 mb-3">
					Comma-separated list of authserv-id values (e.g. <code className="text-ink">mx.cloudflare.net, mx.google.com</code>).
					Only <code className="text-ink">Authentication-Results</code> headers matching these authservs contribute to the SPF/DKIM/DMARC verdict —
					this prevents an attacker-controlled upstream relay from forging a pass verdict.
					Leave empty to trust any authserv (less secure).
				</p>
				<ListInput
					value={s.trusted_authserv_ids ?? []}
					onChange={(next) => patch({ trusted_authserv_ids: next })}
					placeholder="mx.cloudflare.net, mx.google.com"
					disabled={!s.enabled}
				/>
			</div>

			{/* Allowlists */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-2">Allowlists (hard-allow when DMARC passes)</div>
				<p className="text-xs text-ink-3 mb-3">
					Matched senders skip the classifier and are allowed — <em>only</em> when DMARC also passes.
					Without the DMARC requirement, the allowlist alone would let any attacker spoof a trusted From: address.
				</p>
				<p className="text-xs text-ink-3 mb-3">
					<strong>Inheritance:</strong> per-mailbox entries here <em>extend</em>
					the org allowlists rather than replacing them. Resolved list is the
					deduped, lowercased union with org entries first. Every other security
					field on this panel is whole-replace: setting it here shadows the
					upstream tier's value entirely.
				</p>
				<div className="space-y-3">
					<ListInput
						label="Allowed senders (comma-separated)"
						value={s.allowlist_senders ?? []}
						onChange={(next) => patch({ allowlist_senders: next })}
						placeholder="ceo@company.com, payroll@vendor.com"
						disabled={!s.enabled}
					/>
					<ListInput
						label="Allowed domains (comma-separated; subdomains are included)"
						value={s.allowlist_domains ?? []}
						onChange={(next) => patch({ allowlist_domains: next })}
						placeholder="company.com, trustedvendor.com"
						disabled={!s.enabled}
					/>
				</div>
			</div>

			{/* Automations */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-3">Automations</div>
				<div className="space-y-3">
					<Switch
						label="Hard-block on confirmed threat-intel hit"
						checked={s.intel_auto_block ?? true}
						onCheckedChange={(v) => patch({ intel_auto_block: v })}
						disabled={!s.enabled}
					/>
					<Switch
						label="Hard-allow trusted senders"
						checked={s.trusted_auto_allow ?? true}
						onCheckedChange={(v) => patch({ trusted_auto_allow: v })}
						disabled={!s.enabled}
					/>
					<Input
						label="History-based trust: min prior messages"
						type="number"
						min={0}
						value={String(s.trusted_auto_allow_min_messages ?? 10)}
						onChange={(e) => patch({ trusted_auto_allow_min_messages: clampInt(e.target.value, 10, 0, 10_000) })}
						disabled={!s.enabled || s.trusted_auto_allow === false}
					/>
					<p className="text-xs text-ink-3 -mt-2">
						Senders with at least this many prior messages and an average score &lt; 20 auto-allow when DMARC passes.
						Set to 0 to require an explicit allowlist entry.
					</p>

					<Switch
						label="Confidence-aware quarantine (demote low-confidence verdicts to tag)"
						checked={!!s.confidence_aware_actions}
						onCheckedChange={(v) => patch({ confidence_aware_actions: v })}
						disabled={!s.enabled}
					/>
					<p className="text-xs text-ink-3 -mt-2">
						When on, a verdict that would quarantine but whose aggregate pipeline confidence
						is below the threshold is demoted to "tag" instead — routing it for review
						rather than hard quarantine. Useful when the LLM timed out or only one signal
						fired. Off by default; existing mailboxes are unaffected until you enable this.
					</p>
					<Input
						label="Min confidence for quarantine (0–1)"
						type="number"
						min={0}
						max={1}
						step={0.05}
						value={String(s.min_confidence_for_quarantine ?? 0.6)}
						onChange={(e) => patch({ min_confidence_for_quarantine: clampConfidence(e.target.value, 0.6) })}
						disabled={!s.enabled || !s.confidence_aware_actions}
					/>
					<p className="text-xs text-ink-3 -mt-2">
						Quarantine verdicts with confidence strictly below this value are demoted to tag.
						Default 0.6. Raise to catch more uncertain verdicts; lower to only rescue
						extremely shaky ones.
					</p>
				</div>
			</div>

			{/* Classifier */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-2">Classifier</div>
				<p className="text-xs text-ink-3 mb-3">
					Controls what happens when the LLM classifier times out or returns an error.
					The default (on) is fail-open: a timeout contributes 0 to the verdict and tags the
					email as <code className="text-ink">llm_unavailable</code>, so transient
					Workers AI throttling or cold starts don&apos;t send legitimate mail to quarantine.
					Disable to restore the legacy fail-closed-to-<code className="text-ink">suspicious</code> behavior.
				</p>
				<Switch
					label="Skip classification on timeout (fail-open)"
					checked={s.classification?.skip_on_timeout ?? true}
					onCheckedChange={(v) => patch({ classification: { ...s.classification, skip_on_timeout: v } })}
					disabled={!s.enabled}
				/>
			</div>

			{/* DMARC RUF ingestion */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-2">DMARC forensic report ingestion (RUF)</div>
				<p className="text-xs text-ink-3 mb-3">
					Opt-in ingestion of DMARC RUF forensic failure reports (RFC 6591). When enabled,
					reports delivered to this mailbox are parsed and stored for investigation on the
					domain detail page. Disabled by default — enabling this retains per-message
					authentication metadata, so only enable on mailboxes you control and review.
				</p>
				<div className="space-y-3">
					<Switch
						label="Enable RUF forensic report ingestion"
						checked={!!(s.ruf_ingestion?.enabled)}
						onCheckedChange={(v) => patch({ ruf_ingestion: { ...s.ruf_ingestion, enabled: v, retain_raw: s.ruf_ingestion?.retain_raw ?? false } })}
						disabled={!s.enabled}
					/>
					<Switch
						label="Retain original message headers (privacy-sensitive)"
						checked={!!(s.ruf_ingestion?.retain_raw)}
						onCheckedChange={(v) => patch({ ruf_ingestion: { ...s.ruf_ingestion, enabled: s.ruf_ingestion?.enabled ?? false, retain_raw: v } })}
						disabled={!s.enabled || !s.ruf_ingestion?.enabled}
					/>
					<p className="text-xs text-ink-3 -mt-2">
						When on, the header block of the original failing message is stored with
						<code className="text-ink"> To</code>,{" "}
						<code className="text-ink">Cc</code>,{" "}
						<code className="text-ink">Bcc</code>, and{" "}
						<code className="text-ink">Subject</code> redacted. When off, only the
						machine-readable ARF fields (IP, domain, failure type) are stored.
					</p>
				</div>
			</div>

			{/* Scoring mitigations */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-2">Scoring mitigations</div>
				<p className="text-xs text-ink-3 mb-3">
					Compensating-control adjustments applied after per-signal scoring. When on, DMARC=pass
					zeroes out the SPF and DKIM per-method fail contributions — a passing DMARC already
					proves alignment, so penalising the individual method double-counts the failure and
					inflates scores for mailing-list and forwarded mail. Disable only if you need strict
					per-method failure scoring regardless of DMARC outcome.
				</p>
				<Switch
					label="DMARC=pass cancels per-method SPF/DKIM fail contributions"
					checked={s.mitigations?.dmarc_pass_compensates_method_fail ?? true}
					onCheckedChange={(v) => patch({ mitigations: { ...s.mitigations, dmarc_pass_compensates_method_fail: v } })}
					disabled={!s.enabled}
				/>
			</div>

			{/* Detectors */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-2">Detectors</div>
				<p className="text-xs text-ink-3 mb-3">
					The sender-graph / BEC detector builds a per-mailbox graph of prior senders and
					flags display-name impersonation — mail whose display name matches a known contact
					but whose address does not. On by default; disable for a mailbox that receives
					high-volume bulk mail where display-name reuse is expected and not a risk signal.
				</p>
				<Switch
					label="Sender-graph / BEC detector"
					checked={s.detectors?.sender_graph?.enabled ?? true}
					onCheckedChange={(v) => patch({
						detectors: { ...s.detectors, sender_graph: { ...s.detectors?.sender_graph, enabled: v } },
					})}
					disabled={!s.enabled}
				/>
			</div>

			{/* Business hours */}
			<div className="border-t border-line pt-5">
				<div className="text-xs font-medium text-ink mb-2">Business hours</div>
				<p className="text-xs text-ink-3 mb-3">
					Adds a small score nudge (+10) to mail received outside your working hours —
					BEC/wire-fraud asks disproportionately land at 3am and on weekends.
					Scoring only; never short-circuits to quarantine on time alone.
				</p>
				<Switch
					label="Boost score on off-hours delivery"
					checked={!!bh?.boost_on_off_hours}
					onCheckedChange={(v) => patch({
						business_hours: { ...(bh ?? DEFAULT_BUSINESS_HOURS), boost_on_off_hours: v },
					})}
					disabled={!s.enabled}
				/>
				<div className="grid grid-cols-2 gap-3 mt-3">
					<Input
						label="Timezone (IANA)"
						value={bh?.timezone ?? ""}
						onChange={(e) => patch({
							business_hours: { ...(bh ?? DEFAULT_BUSINESS_HOURS), timezone: e.target.value },
						})}
						placeholder="America/New_York"
						disabled={!s.enabled || !bh?.boost_on_off_hours}
					/>
					<Switch
						label="Weekdays only"
						checked={bh?.weekdays_only ?? true}
						onCheckedChange={(v) => patch({
							business_hours: { ...(bh ?? DEFAULT_BUSINESS_HOURS), weekdays_only: v },
						})}
						disabled={!s.enabled || !bh?.boost_on_off_hours}
					/>
					<Input
						label="Start hour (0–23, local)"
						type="number"
						min={0}
						max={23}
						value={String(bh?.start_hour ?? 9)}
						onChange={(e) => patch({
							business_hours: { ...(bh ?? DEFAULT_BUSINESS_HOURS), start_hour: clampInt(e.target.value, 9, 0, 23) },
						})}
						disabled={!s.enabled || !bh?.boost_on_off_hours}
					/>
					<Input
						label="End hour (exclusive, 0–23)"
						type="number"
						min={0}
						max={23}
						value={String(bh?.end_hour ?? 18)}
						onChange={(e) => patch({
							business_hours: { ...(bh ?? DEFAULT_BUSINESS_HOURS), end_hour: clampInt(e.target.value, 18, 0, 23) },
						})}
						disabled={!s.enabled || !bh?.boost_on_off_hours}
					/>
				</div>
			</div>

			{/* Attachment filtering */}
			<details className="border-t border-line pt-5 group">
				<summary className="cursor-pointer list-none flex items-center justify-between">
					<span className="text-xs font-medium text-ink">Attachment filtering</span>
					<span className="text-xs text-ink-3 group-open:hidden">Show</span>
					<span className="text-xs text-ink-3 hidden group-open:inline">Hide</span>
				</summary>
				<p className="text-xs text-ink-3 mt-3 mb-4">
					How the attachment-type gate handles risky filetypes. Runs before the LLM
					classifier so a known-bad attachment never spends LLM budget. Custom blocklist
					entries always hard-block, even on a trusted/allowlisted sender.
				</p>

				<div className="space-y-5">
					<AttachmentActionGroup
						label="Executable files"
						helper="Includes .exe, .scr, .com, .msi, .jar, .js, .vbs, .ps1, .bat, .lnk, and similar."
						value={attachment.executable_action ?? DEFAULT_ATTACHMENT_POLICY.executable_action}
						onChange={(v) => patchAttachment({ executable_action: v })}
						disabled={!s.enabled}
					/>
					<AttachmentActionGroup
						label="Container files"
						helper="Includes .iso, .img, .vhd, .vhdx — commonly used to smuggle executables past gateways that block .exe directly."
						value={attachment.container_action ?? DEFAULT_ATTACHMENT_POLICY.container_action}
						onChange={(v) => patchAttachment({ container_action: v })}
						disabled={!s.enabled}
					/>
					<AttachmentActionGroup
						label="Macro-enabled Office files"
						helper="Includes .docm, .xlsm, .pptm, .xlam, .xltm, .potm, .ppsm — macros are the classic malware delivery path."
						value={attachment.macro_office_action ?? DEFAULT_ATTACHMENT_POLICY.macro_office_action}
						onChange={(v) => patchAttachment({ macro_office_action: v })}
						disabled={!s.enabled}
					/>

					<div>
						<ListInput
							label="Custom blocklist (extensions)"
							value={attachment.custom_blocklist_extensions ?? []}
							onChange={(next) => patchAttachment({ custom_blocklist_extensions: next })}
							parse={parseExtensionList}
							placeholder="dmg, rtf"
							disabled={!s.enabled}
						/>
						<p className="text-xs text-ink-3 mt-2">
							Lowercase, no leading dot. e.g. <code className="text-ink">dmg, rtf</code>.
							Anything listed here always hard-blocks, regardless of sender trust.
						</p>
					</div>
				</div>
			</details>

			{/* Folder rules */}
			<details className="border-t border-line pt-5 group">
				<summary className="cursor-pointer list-none flex items-center justify-between">
					<span className="text-xs font-medium text-ink">Folder rules</span>
					<span className="text-xs text-ink-3 group-open:hidden">Show</span>
					<span className="text-xs text-ink-3 hidden group-open:inline">Hide</span>
				</summary>
				<p className="text-xs text-ink-3 mt-3 mb-4">
					Per-folder bypasses and trust signals. <strong>Skip classifier</strong> keeps the
					rest of the pipeline (auth, URLs, intel) running but skips the LLM.
					<strong> Skip all</strong> bypasses the entire pipeline — use only on folders an
					attacker cannot deliver into. <strong>Treat moves here as verified</strong> bumps a
					sender's reputation when you move their mail into the folder.
				</p>

				<div className="space-y-4">
					{SYSTEM_FOLDER_IDS.map((folderId) => {
						const policy = folders[folderId] ?? {};
						return (
							<FolderPolicyRow
								key={folderId}
								folderId={folderId}
								label={FOLDER_DISPLAY_NAMES[folderId] ?? folderId}
								policy={policy}
								disabled={!s.enabled}
								onChange={(next) => patchFolder(folderId, next)}
							/>
						);
					})}
				</div>
			</details>
		</div>
	);
}

interface AttachmentActionGroupProps {
	label: string;
	helper: string;
	value: AttachmentAction;
	onChange: (next: AttachmentAction) => void;
	disabled?: boolean;
}

function AttachmentActionGroup({ label, helper, value, onChange, disabled }: AttachmentActionGroupProps) {
	const id = label.replace(/\s+/g, "-").toLowerCase();
	return (
		<fieldset disabled={disabled} className="space-y-2">
			<legend className="text-sm text-ink">{label}</legend>
			<p className="text-xs text-ink-3">{helper}</p>
			<div role="radiogroup" aria-label={label} className="flex gap-4">
				{(["block", "score", "ignore"] as const).map((action) => (
					<label key={action} className="flex items-center gap-2 text-xs text-ink-2">
						<input
							type="radio"
							name={`attachment-${id}`}
							value={action}
							checked={value === action}
							onChange={() => onChange(action)}
							disabled={disabled}
							className="h-3.5 w-3.5 accent-accent"
						/>
						<span className="capitalize">{action}</span>
					</label>
				))}
			</div>
		</fieldset>
	);
}

interface FolderPolicyRowProps {
	folderId: string;
	label: string;
	policy: FolderPolicySettings;
	disabled?: boolean;
	onChange: (next: FolderPolicySettings | undefined) => void;
}

function FolderPolicyRow({ folderId, label, policy, disabled, onChange }: FolderPolicyRowProps) {
	const skipAll = policy.mode === "skip_all";
	const skipClassifier = policy.mode === "skip_classifier";
	const treatAsVerified = !!policy.treat_as_verified;

	const update = (next: Partial<FolderPolicySettings>) => onChange({ ...policy, ...next });

	const onSkipClassifier = (checked: boolean) => {
		// Mode is mutex on the server side: setting one clears the other.
		// `skip_all` is the strict superset, so it stays winning when both
		// would be on.
		if (checked) {
			update({ mode: skipAll ? "skip_all" : "skip_classifier" });
		} else {
			update({ mode: skipAll ? "skip_all" : undefined });
		}
	};
	const onSkipAll = (checked: boolean) => {
		if (checked) update({ mode: "skip_all" });
		else update({ mode: skipClassifier ? "skip_classifier" : undefined });
	};
	const onTreatVerified = (checked: boolean) => update({ treat_as_verified: checked || undefined });

	return (
		<div className="rounded-md border border-line p-3">
			<div className="text-sm text-ink mb-2">{label}</div>
			<div className="space-y-2">
				<label className="flex items-center gap-2 text-xs text-ink-2">
					<input
						type="checkbox"
						checked={skipClassifier && !skipAll}
						onChange={(e) => onSkipClassifier(e.target.checked)}
						disabled={disabled || skipAll}
						aria-label={`Skip classifier on ${label}`}
						data-testid={`skip-classifier-${folderId}`}
						className="h-3.5 w-3.5 accent-accent"
					/>
					<span>Skip classifier</span>
				</label>
				<label className="flex items-center gap-2 text-xs text-ink-2">
					<input
						type="checkbox"
						checked={treatAsVerified}
						onChange={(e) => onTreatVerified(e.target.checked)}
						disabled={disabled}
						aria-label={`Treat moves to ${label} as verified`}
						data-testid={`treat-verified-${folderId}`}
						className="h-3.5 w-3.5 accent-accent"
					/>
					<span>Treat moves here as verified</span>
				</label>
				<label className="flex items-center gap-2 text-xs text-red-500">
					<input
						type="checkbox"
						checked={skipAll}
						onChange={(e) => onSkipAll(e.target.checked)}
						disabled={disabled}
						aria-label={`Skip all on ${label}`}
						data-testid={`skip-all-${folderId}`}
						className="h-3.5 w-3.5 accent-red-500"
					/>
					<span>Skip all (bypass entire pipeline — only safe on folders an attacker cannot deliver into)</span>
				</label>
			</div>
		</div>
	);
}

interface ListInputProps {
	value: string[];
	onChange: (next: string[]) => void;
	parse?: (raw: string) => string[];
	label?: string;
	placeholder?: string;
	disabled?: boolean;
}

/**
 * Input bound to a `string[]` via comma-separated text.
 *
 * The naive pattern (`value={array.join(", ")}` + parse-on-change) collapses
 * partial entries: typing the comma re-emits the parsed array, the controlled
 * value drops the trailing separator, and the next character lands appended
 * to the previous entry. Repro: typing `dmg, rtf, ace` into such an input
 * yields a single `["dmgrtface"]` instead of three entries.
 *
 * Fix: hold the raw string locally so the user's separators survive between
 * keystrokes; emit the parsed array on every change for the parent's
 * Save-on-click flow; only resync the displayed text when the parent's value
 * diverges from what we last emitted (external load, reset).
 */
function ListInput({
	value,
	onChange,
	parse = parseList,
	label,
	placeholder,
	disabled,
}: ListInputProps) {
	const [draft, setDraft] = useState(() => value.join(", "));
	const lastEmitted = useRef<string[]>(value);

	useEffect(() => {
		if (!arraysEqual(value, lastEmitted.current)) {
			lastEmitted.current = value;
			setDraft(value.join(", "));
		}
	}, [value]);

	return (
		<Input
			label={label}
			placeholder={placeholder}
			disabled={disabled}
			value={draft}
			onChange={(e) => {
				const raw = e.target.value;
				setDraft(raw);
				const parsed = parse(raw);
				if (!arraysEqual(parsed, lastEmitted.current)) {
					lastEmitted.current = parsed;
					onChange(parsed);
				}
			}}
		/>
	);
}

function arraysEqual(a: string[], b: string[]): boolean {
	if (a === b) return true;
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}

function parseList(raw: string): string[] {
	return raw
		.split(",")
		.map((s) => s.trim().toLowerCase())
		.filter(Boolean);
}

/** Like parseList but also strips a leading dot, so users can paste either
 *  `dmg, rtf` or `.dmg, .rtf` without breaking the consumer's match logic. */
function parseExtensionList(raw: string): string[] {
	return raw
		.split(",")
		.map((s) => s.trim().toLowerCase().replace(/^\./, ""))
		.filter(Boolean);
}

function clampScore(raw: string, fallback: number): number {
	return clampInt(raw, fallback, 0, 100);
}

function clampConfidence(raw: string, fallback: number): number {
	const n = parseFloat(raw);
	if (!Number.isFinite(n)) return fallback;
	return Math.max(0, Math.min(1, Math.round(n * 100) / 100));
}

function clampInt(raw: string, fallback: number, min: number, max: number): number {
	const n = parseInt(raw, 10);
	if (!Number.isFinite(n)) return fallback;
	return Math.max(min, Math.min(max, n));
}
