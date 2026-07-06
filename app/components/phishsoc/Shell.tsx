import {
	BriefcaseIcon,
	BuildingsIcon,
	CaretDownIcon,
	CaretRightIcon,
	EnvelopeIcon,
	GaugeIcon,
	GearSixIcon,
	GlobeIcon,
	GraphIcon,
	ListIcon,
	MagnifyingGlassIcon,
	MoonIcon,
	SparkleIcon,
	StarIcon,
	SunIcon,
	TrayIcon,
	XIcon,
} from "@phosphor-icons/react";
import {
	type FormEvent,
	type ReactNode,
	useCallback,
	useEffect,
	useRef,
	useState,
} from "react";
import {
	NavLink,
	useLocation,
	useMatch,
	useNavigate,
	useParams,
} from "react-router";
import { useUIStore } from "~/hooks/useUIStore";
import { useDashboardSummary } from "~/queries/dashboard";
import { useDomainStats } from "~/queries/domains";
import { useFolders } from "~/queries/folders";
import { useMailbox, useMailboxes } from "~/queries/mailboxes";
import { useMe } from "~/queries/me";
import { SYSTEM_FOLDER_IDS, getFolderDisplayName } from "shared/folders";
import type { DomainMailboxRef, Folder, Mailbox } from "~/types";
import AccountMenu from "./AccountMenu";
import AgentPanelSlot from "./AgentPanelSlot";
import Breadcrumb from "./Breadcrumb";
import Logo from "./Logo";
import MailboxSwitcher from "./MailboxSwitcher";
import NotificationsBell from "./NotificationsBell";
import OrgAgentPanel from "./OrgAgentPanel";

type PipelineTone = "safe" | "suspect" | "danger" | "muted";

interface PipelineState {
	tone: PipelineTone;
	label: string;
	pulse: boolean;
}

// Map the dashboard summary's pipelineSuccess (0..1, or null) to a visible
// pill state. Thresholds match the issue spec (#86): >=0.95 healthy, >=0.5
// degraded, otherwise failing. Null/loading shows muted "No data" — never a
// fake-green dot.
function computePipelineState(
	pipelineSuccess: number | null | undefined,
): PipelineState {
	if (pipelineSuccess == null) {
		return { tone: "muted", label: "No data", pulse: false };
	}
	if (pipelineSuccess >= 0.95) {
		return { tone: "safe", label: "Pipeline online", pulse: true };
	}
	if (pipelineSuccess >= 0.5) {
		return { tone: "suspect", label: "Degraded", pulse: false };
	}
	return { tone: "danger", label: "Pipeline failing", pulse: false };
}

const PIPELINE_DOT_BG: Record<PipelineTone, string> = {
	safe: "bg-safe",
	suspect: "bg-suspect",
	danger: "bg-danger",
	muted: "bg-ink-4",
};

interface NavItemProps {
	to: string;
	icon: ReactNode;
	label: string;
	count?: number | string;
	end?: boolean;
}

function NavItem({ to, icon, label, count, end }: NavItemProps) {
	return (
		<NavLink
			to={to}
			end={end}
			className={({ isActive }) =>
				`relative flex items-center gap-2.5 px-3 py-1.5 rounded-md text-[13px] transition-colors ${
					isActive
						? "bg-paper-3 text-ink"
						: "text-ink-2 hover:bg-paper-2 hover:text-ink"
				}`
			}
		>
			{({ isActive }) => (
				<>
					{isActive && (
						<span
							aria-hidden
							className="absolute left-[-12px] top-1/2 -translate-y-1/2 h-4 w-[2px] rounded-full bg-accent"
						/>
					)}
					<span className="shrink-0 text-current">{icon}</span>
					<span className="flex-1 truncate">{label}</span>
					{count !== undefined && (
						<span className="pp-mono text-[11px] text-ink-3 tabular-nums">
							{count}
						</span>
					)}
				</>
			)}
		</NavLink>
	);
}

function SectionLabel({ children }: { children: ReactNode }) {
	return (
		<div className="px-3 pt-4 pb-1.5 text-[10.5px] uppercase tracking-[0.08em] text-ink-3">
			{children}
		</div>
	);
}

// ---------------------------------------------------------------------------
// Folder nav localStorage helpers — per-mailbox, client-side only.
// Key format: `phishsoc-folder-nav-<mailboxId>`
// ---------------------------------------------------------------------------

interface FolderNavPrefs {
	/** IDs of pinned/favorite folders */
	favorites: string[];
	/** Whether the folder section is collapsed */
	collapsed: boolean;
}

const FOLDER_NAV_STORAGE_PREFIX = "phishsoc-folder-nav-";

function loadFolderNavPrefs(mailboxId: string): FolderNavPrefs {
	if (typeof window === "undefined") return { favorites: [], collapsed: false };
	try {
		const raw = localStorage.getItem(
			`${FOLDER_NAV_STORAGE_PREFIX}${mailboxId}`,
		);
		if (raw) {
			const parsed = JSON.parse(raw) as Partial<FolderNavPrefs>;
			return {
				favorites: Array.isArray(parsed.favorites) ? parsed.favorites : [],
				collapsed:
					typeof parsed.collapsed === "boolean" ? parsed.collapsed : false,
			};
		}
	} catch {
		/* ignore quota / private mode */
	}
	return { favorites: [], collapsed: false };
}

function saveFolderNavPrefs(mailboxId: string, prefs: FolderNavPrefs) {
	if (typeof window === "undefined") return;
	try {
		localStorage.setItem(
			`${FOLDER_NAV_STORAGE_PREFIX}${mailboxId}`,
			JSON.stringify(prefs),
		);
	} catch {
		/* ignore quota / private mode */
	}
}

/**
 * Sort folders: system folders first (per SYSTEM_FOLDER_IDS order), then
 * custom folders alphabetically.
 */
function sortFolders(folders: Folder[]): Folder[] {
	return [...folders].sort((a, b) => {
		const ai = SYSTEM_FOLDER_IDS.indexOf(
			a.id as (typeof SYSTEM_FOLDER_IDS)[number],
		);
		const bi = SYSTEM_FOLDER_IDS.indexOf(
			b.id as (typeof SYSTEM_FOLDER_IDS)[number],
		);
		// Both system folders — use SYSTEM_FOLDER_IDS order
		if (ai !== -1 && bi !== -1) return ai - bi;
		// Only a is a system folder
		if (ai !== -1) return -1;
		// Only b is a system folder
		if (bi !== -1) return 1;
		// Both custom — alphabetical
		return a.name.localeCompare(b.name);
	});
}

interface FolderNavProps {
	mailboxId: string;
	folders: Folder[];
	base: string;
}

function FolderNav({ mailboxId, folders, base }: FolderNavProps) {
	const [prefs, setPrefs] = useState<FolderNavPrefs>(() =>
		loadFolderNavPrefs(mailboxId),
	);

	// Re-load prefs when the mailboxId changes (user switches mailbox)
	useEffect(() => {
		setPrefs(loadFolderNavPrefs(mailboxId));
	}, [mailboxId]);

	const toggleCollapsed = useCallback(() => {
		setPrefs((prev) => {
			const next = { ...prev, collapsed: !prev.collapsed };
			saveFolderNavPrefs(mailboxId, next);
			return next;
		});
	}, [mailboxId]);

	const toggleFavorite = useCallback(
		(folderId: string) => {
			setPrefs((prev) => {
				const isFav = prev.favorites.includes(folderId);
				const next = {
					...prev,
					favorites: isFav
						? prev.favorites.filter((id) => id !== folderId)
						: [...prev.favorites, folderId],
				};
				saveFolderNavPrefs(mailboxId, next);
				return next;
			});
		},
		[mailboxId],
	);

	const sorted = sortFolders(folders);
	const favorites = sorted.filter((f) => prefs.favorites.includes(f.id));
	const rest = sorted.filter((f) => !prefs.favorites.includes(f.id));

	const contentId = "folder-list-content";

	return (
		<>
			{/* Collapsible section header */}
			<button
				type="button"
				onClick={toggleCollapsed}
				className="w-full flex items-center gap-1 px-3 pt-4 pb-1.5 text-[10.5px] uppercase tracking-[0.08em] text-ink-3 hover:text-ink-2 transition-colors"
				aria-expanded={!prefs.collapsed}
				aria-controls={contentId}
			>
				<span className="flex-1 text-left">Folders</span>
				{prefs.collapsed ? (
					<CaretRightIcon size={10} aria-hidden />
				) : (
					<CaretDownIcon size={10} aria-hidden />
				)}
			</button>

			{!prefs.collapsed && (
				<div id={contentId} className="flex flex-col">
					{/* Favorites pinned at top */}
					{favorites.map((folder) => (
						<FolderNavItem
							key={folder.id}
							folder={folder}
							base={base}
							isFavorite
							onToggleFavorite={toggleFavorite}
						/>
					))}
					{/* Rest of folders */}
					{rest.map((folder) => (
						<FolderNavItem
							key={folder.id}
							folder={folder}
							base={base}
							isFavorite={false}
							onToggleFavorite={toggleFavorite}
						/>
					))}
				</div>
			)}
		</>
	);
}

interface FolderNavItemProps {
	folder: Folder;
	base: string;
	isFavorite: boolean;
	onToggleFavorite: (id: string) => void;
}

function FolderNavItem({
	folder,
	base,
	isFavorite,
	onToggleFavorite,
}: FolderNavItemProps) {
	return (
		<div className="group relative flex items-center">
			<NavLink
				to={`${base}/emails/${folder.id}`}
				className={({ isActive }) =>
					`flex-1 flex items-center gap-2.5 px-3 py-1.5 rounded-md text-[13px] transition-colors ${
						isActive
							? "bg-paper-3 text-ink"
							: "text-ink-2 hover:bg-paper-2 hover:text-ink"
					}`
				}
			>
				{({ isActive }) => (
					<>
						{isActive && (
							<span
								aria-hidden
								className="absolute left-[-12px] top-1/2 -translate-y-1/2 h-4 w-[2px] rounded-full bg-accent"
							/>
						)}
						<span className="shrink-0 text-current">
							<TrayIcon size={16} />
						</span>
						<span className="flex-1 truncate">
							{getFolderDisplayName(folder.id)}
						</span>
						{folder.unreadCount > 0 && (
							<span className="pp-mono text-[11px] text-ink-3 tabular-nums">
								{folder.unreadCount}
							</span>
						)}
					</>
				)}
			</NavLink>
			{/* Favorite/pin toggle — only visible on hover */}
			<button
				type="button"
				onClick={() => onToggleFavorite(folder.id)}
				aria-label={
					isFavorite
						? `Unpin ${getFolderDisplayName(folder.id)}`
						: `Pin ${getFolderDisplayName(folder.id)}`
				}
				className={`absolute right-1.5 flex h-5 w-5 shrink-0 items-center justify-center rounded transition-colors ${
					isFavorite
						? "text-accent opacity-100"
						: "text-ink-4 opacity-0 group-hover:opacity-100 hover:text-ink-2"
				}`}
			>
				<StarIcon size={12} weight={isFavorite ? "fill" : "regular"} />
			</button>
		</div>
	);
}

interface NavContentsProps {
	mailboxId: string | undefined;
	mailbox: { name?: string | null; email?: string | null } | undefined;
	mailboxes: Mailbox[] | undefined;
	mailboxCount: number;
	pipelineState: PipelineState;
	theme: "light" | "dark";
	onToggleTheme: () => void;
	onCloseSidebar: () => void;
	onPipelineClick: () => void;
	/** Authenticated-user email from `/api/v1/me` (#204). Undefined while
	 * the query is in flight; AccountMenu handles the loading label. */
	meEmail: string | undefined;
	/**
	 * When the current route is `/domains/:domain`, the active domain plus
	 * the mailboxes that belong to it (#139). Both fields are gated so other
	 * routes never pay the network cost: `domain` is `undefined` off-route,
	 * and `domainMailboxes` is `undefined` while the query is pending so the
	 * sidebar can fall back to the org-level nav instead of flashing an
	 * empty list.
	 */
	domain: string | undefined;
	domainMailboxes: DomainMailboxRef[] | undefined;
	/**
	 * Folders for the current mailbox. Undefined while the query is pending
	 * so the sidebar can fall back gracefully rather than flashing an empty
	 * list. Only defined when `mailboxId` is set.
	 */
	folders: Folder[] | undefined;
}

// Shared sidebar contents — rendered inline on `md+` and inside the mobile
// drawer on `<md`. Keeping a single source of truth here means the next
// nav-item addition only has to touch one place.
function NavContents({
	mailboxId,
	mailbox,
	mailboxes,
	mailboxCount,
	pipelineState,
	theme,
	onToggleTheme,
	onCloseSidebar,
	onPipelineClick,
	domain,
	domainMailboxes,
	meEmail,
	folders,
}: NavContentsProps) {
	const base = mailboxId ? `/mailbox/${encodeURIComponent(mailboxId)}` : "";

	return (
		<>
			<div className="px-4 pt-4 pb-3">
				<Logo />
			</div>

			{/* Mailbox switcher (#188). Replaces the old "Select mailbox" card,
			    which was wired to `navigate("/")` and therefore a no-op at the
			    org root. The new card opens a base-ui Menu listing every
			    mailbox the user has access to; selecting one navigates to the
			    per-mailbox dashboard. */}
			{/* `mailboxes` prop here is the inbox-navigable (non-sidecar) subset —
			    see the `inboxMailboxes` filter at the Shell call site below. */}
			<MailboxSwitcher
				activeMailboxId={mailboxId}
				mailbox={mailbox}
				mailboxes={mailboxes}
				mailboxCount={mailboxCount}
				onClose={onCloseSidebar}
			/>

			<nav className="mt-3 px-3 flex-1 overflow-y-auto">
				{/* Org-scoped entries are always visible. They route to / and
				    /mailboxes respectively, regardless of which mailbox is
				    currently selected. */}
				<NavItem
					to="/"
					end
					icon={<BuildingsIcon size={16} />}
					label="Org overview"
				/>
				<NavItem
					to="/mailboxes"
					icon={<EnvelopeIcon size={16} />}
					label="Mailboxes"
					count={mailboxCount > 0 ? mailboxCount : undefined}
				/>
				<NavItem to="/domains" icon={<GlobeIcon size={16} />} label="Domains" />
				{/* Org-wide settings (#153) — surfaced as a top-level entry so
				    operators can reach `/settings` from a cold start, without
				    first picking a mailbox. The per-mailbox `Settings` entry
				    below is unaffected; that one stays mailbox-scoped. */}
				<NavItem
					to="/settings"
					end
					icon={<GearSixIcon size={16} />}
					label="Org settings"
				/>
				{mailboxId && (
					<>
						<SectionLabel>This mailbox</SectionLabel>
						<NavItem
							to={`${base}/dashboard`}
							icon={<GaugeIcon size={16} />}
							label="Dashboard"
						/>
						<NavItem
							to={`${base}/cases`}
							icon={<BriefcaseIcon size={16} />}
							label="Cases"
						/>
						{/* Dynamic folder navigation section. Only rendered once
						    the query has resolved — while pending we fall through
						    rather than flashing an empty list (mirrors the
						    domain-mailboxes guard above). */}
						{folders && folders.length > 0 && (
							<FolderNav mailboxId={mailboxId} folders={folders} base={base} />
						)}
						<NavItem
							to={`${base}/hub`}
							icon={<GraphIcon size={16} />}
							label="Threat-intel hub"
						/>
						<SectionLabel>System</SectionLabel>
						<NavItem
							to={`${base}/settings`}
							icon={<GearSixIcon size={16} />}
							label="Settings"
						/>
					</>
				)}
				{/* Domain-scoped block (#139 / #547): on `/domains/:domain[/*]` show
				    a persistent settings link (derived from the route match,
				    no data-load gate) plus the mailbox list once loaded. */}
				{domain && (
					<>
						<SectionLabel>This domain</SectionLabel>
						<NavItem
							to={`/domains/${encodeURIComponent(domain)}/settings`}
							icon={<GearSixIcon size={16} />}
							label="Domain settings"
						/>
						{domainMailboxes && domainMailboxes.length > 0 && (
							<>
								<SectionLabel>Mailboxes in {domain}</SectionLabel>
								{domainMailboxes.map((mb) => (
									<NavItem
										key={mb.id}
										to={`/mailbox/${encodeURIComponent(mb.id)}/dashboard`}
										icon={<EnvelopeIcon size={16} />}
										label={mb.email || mb.name || mb.id}
									/>
								))}
							</>
						)}
					</>
				)}
			</nav>

			{/* Pipeline status pill. State derives from the dashboard summary's
			    `pipelineSuccess` (#86); real p95 latency is now surfaced as a
			    KPI on the Operations dashboard (#71). The pill stays scoped to
			    success/failure so the sidebar reads as a status indicator
			    rather than a metric. */}
			{mailboxId && (
				<button
					type="button"
					role="status"
					aria-live="polite"
					aria-label={`Pipeline status: ${pipelineState.label}`}
					onClick={onPipelineClick}
					className="mx-3 mb-3 flex items-center gap-2 rounded-md border border-line bg-paper px-2.5 py-1.5 text-left hover:border-line-strong transition-colors"
				>
					<span className="relative flex h-2 w-2">
						{pipelineState.pulse && (
							<span
								aria-hidden
								className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${PIPELINE_DOT_BG[pipelineState.tone]}`}
							/>
						)}
						<span
							aria-hidden
							className={`relative inline-flex h-2 w-2 rounded-full ${PIPELINE_DOT_BG[pipelineState.tone]}`}
						/>
					</span>
					<span className="text-[11px] text-ink-2">{pipelineState.label}</span>
				</button>
			)}

			{/* Auth-aware account menu (#204). The avatar + email row is the
			    Menu trigger; the popover hosts links to /settings and the
			    Cloudflare Access sign-out. The theme toggle stays sibling-
			    visible (right-justified) so it's reachable without opening
			    the menu — the issue's "Theme toggle remains reachable"
			    constraint. */}
			<div className="border-t border-line px-3 py-2 flex items-center gap-1">
				<AccountMenu email={meEmail} onClose={onCloseSidebar} />
				<button
					type="button"
					onClick={onToggleTheme}
					className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-ink-3 hover:bg-paper-3 hover:text-ink transition-colors"
					aria-label={
						theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
					}
				>
					{theme === "dark" ? <SunIcon size={14} /> : <MoonIcon size={14} />}
				</button>
			</div>
		</>
	);
}

interface ShellProps {
	children: ReactNode;
	/**
	 * Optional right-hand content that shares the main column. Today this hosts
	 * the agent + MCP panel (#82); the slot is responsible for choosing
	 * in-flow (xl+) vs slide-over (<xl) rendering based on viewport.
	 */
	rightPanel?: ReactNode;
}

export default function Shell({ children, rightPanel }: ShellProps) {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const navigate = useNavigate();
	const location = useLocation();
	const {
		theme,
		toggleTheme,
		isSidebarOpen,
		openSidebar,
		closeSidebar,
		isAgentPanelOpen,
		toggleAgentPanel,
	} = useUIStore();
	const { data: mailbox } = useMailbox(mailboxId);
	const { data: mailboxes } = useMailboxes();
	const mailboxCount = mailboxes?.length ?? 0;
	// Sidecar mailboxes (#31) don't have an inbox view — they're managed from
	// settings only — so the switcher (inbox navigation) excludes them.
	const inboxMailboxes = mailboxes?.filter((m) => !m.sidecar);
	// Authenticated identity for the sidebar account menu (#204). Hoisted
	// to Shell so the same hook covers both the desktop sidebar render and
	// the mobile drawer render — only one fetch per page, not two.
	const { data: me } = useMe();

	// Folder list for the dynamic sidebar nav (#366). Enabled only when a
	// mailbox is active; the hook's `enabled: !!mailboxId` guard keeps other
	// routes from paying the network cost.
	const { data: folders } = useFolders(mailboxId);

	const { data: dashboardSummary } = useDashboardSummary(mailboxId);
	const pipelineState = computePipelineState(dashboardSummary?.pipelineSuccess);

	// `/domains/:domain` (#139). Use a route match rather than `useParams`
	// because Shell can be rendered from either the per-domain route or the
	// per-mailbox route; only the former should pull domain stats. The
	// `useDomainStats` hook is `enabled: !!domain` internally, so passing
	// `undefined` off-route is the gate that keeps other pages from paying
	// the network cost.
	const domainMatchExact = useMatch("/domains/:domain");
	const domainMatchWild = useMatch("/domains/:domain/*");
	const domainMatch = domainMatchExact ?? domainMatchWild;
	const rawDomain = domainMatch?.params.domain;
	const activeDomain = rawDomain ? decodeURIComponent(rawDomain) : undefined;
	const { data: domainStats } = useDomainStats(activeDomain);

	const searchInputRef = useRef<HTMLInputElement>(null);
	const [searchQuery, setSearchQuery] = useState("");

	useEffect(() => {
		// Cmd/Ctrl+K from anywhere focuses the search input. Escape closes the
		// mobile drawer if it's open.
		const onKey = (e: KeyboardEvent) => {
			if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
				e.preventDefault();
				searchInputRef.current?.focus();
				searchInputRef.current?.select();
				return;
			}
			if (e.key === "Escape" && useUIStore.getState().isSidebarOpen) {
				e.preventDefault();
				useUIStore.getState().closeSidebar();
			}
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, []);

	// Close the mobile drawer whenever the route changes. The mailbox-switch
	// effect in routes/mailbox.tsx covers cross-mailbox navigation; this covers
	// in-mailbox nav (Dashboard ↔ Cases etc.), so individual NavItem onClicks
	// don't have to remember to dismiss.
	useEffect(() => {
		closeSidebar();
	}, [location.pathname, closeSidebar]);

	const handleSearchSubmit = (e: FormEvent<HTMLFormElement>) => {
		e.preventDefault();
		const q = searchQuery.trim();
		if (!q) return;
		// On a mailbox-scoped route, scope the search to that mailbox. On every
		// other route (org-level: `/`, `/settings`, `/mailboxes`, `/domains`,
		// `/domains/:domain`) fall back to the org-scope search route (#197).
		if (mailboxId) {
			navigate(
				`/mailbox/${encodeURIComponent(mailboxId)}/search?q=${encodeURIComponent(q)}`,
			);
		} else {
			navigate(`/search?q=${encodeURIComponent(q)}`);
		}
	};

	const navContents = (
		<NavContents
			mailboxId={mailboxId}
			mailbox={mailbox}
			mailboxes={inboxMailboxes}
			mailboxCount={mailboxCount}
			pipelineState={pipelineState}
			theme={theme}
			onToggleTheme={toggleTheme}
			onCloseSidebar={closeSidebar}
			onPipelineClick={() => {
				if (!mailboxId) return;
				closeSidebar();
				navigate(`/mailbox/${encodeURIComponent(mailboxId)}/dashboard`);
			}}
			domain={activeDomain}
			domainMailboxes={domainStats?.mailboxes}
			meEmail={me?.email}
			folders={folders}
		/>
	);

	return (
		<div className="flex h-screen overflow-hidden bg-paper text-ink">
			{/* Sidebar — 232px on desktop. On `<md` the same contents are surfaced
			    via the hamburger drawer below. */}
			<aside className="hidden md:flex w-[232px] shrink-0 flex-col bg-paper-2 border-r border-line">
				{navContents}
			</aside>

			{/* Mobile drawer — backdrop + slide-over. Kept out of the DOM when
			    closed so Esc/click-outside listeners aren't always attached and
			    the desktop test surface stays unchanged. */}
			{isSidebarOpen && (
				<>
					<div
						data-testid="mobile-drawer-backdrop"
						aria-hidden
						className="md:hidden fixed inset-0 z-40 bg-black/50"
						onClick={closeSidebar}
					/>
					<aside
						id="mobile-drawer"
						role="dialog"
						aria-label="Primary navigation"
						className="md:hidden fixed left-0 top-0 bottom-0 z-50 w-[260px] max-w-[85vw] flex flex-col bg-paper-2 border-r border-line shadow-xl"
					>
						<button
							type="button"
							onClick={closeSidebar}
							aria-label="Close menu"
							className="absolute right-2 top-2 flex h-8 w-8 items-center justify-center rounded-md text-ink-3 hover:bg-paper-3 hover:text-ink transition-colors"
						>
							<XIcon size={16} />
						</button>
						{navContents}
					</aside>
				</>
			)}

			{/* Main column. Topbar pinned, content scrolls. */}
			<div className="flex-1 flex flex-col min-w-0">
				<header className="flex items-center gap-3 h-[52px] px-4 md:px-6 border-b border-line bg-paper">
					<button
						type="button"
						onClick={openSidebar}
						aria-label="Open menu"
						aria-expanded={isSidebarOpen}
						aria-controls={isSidebarOpen ? "mobile-drawer" : undefined}
						className="md:hidden flex h-8 w-8 items-center justify-center rounded-md text-ink-3 hover:bg-paper-2 hover:text-ink transition-colors shrink-0"
					>
						<ListIcon size={18} />
					</button>
					<form
						role="search"
						onSubmit={handleSearchSubmit}
						className="flex items-center gap-2 flex-1 max-w-xl"
					>
						<MagnifyingGlassIcon size={14} className="shrink-0 text-ink-3" />
						<input
							ref={searchInputRef}
							type="search"
							value={searchQuery}
							onChange={(e) => setSearchQuery(e.target.value)}
							className="flex-1 bg-transparent border-0 outline-none text-[13px] text-ink placeholder:text-ink-4"
							placeholder="Search emails…  ⌘K"
							aria-label="Search"
						/>
					</form>
					<div className="ml-auto flex items-center gap-1.5 shrink-0">
						<NotificationsBell mailboxId={mailboxId} />
						{/* Mailbox routes pass `rightPanel={<AgentSidebar />}` (the
						    per-mailbox `EmailAgent`-backed chat). Org-level routes
						    pass no `rightPanel` and fall back to the org-scope
						    co-pilot mounted below (#198). Either way the button
						    opens a working panel — the disabled branch from #186
						    is gone. */}
						<button
							type="button"
							onClick={() => toggleAgentPanel()}
							aria-expanded={isAgentPanelOpen}
							aria-controls="agent-panel"
							className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[12px] font-medium transition-colors ${
								isAgentPanelOpen
									? "bg-accent text-paper border-accent hover:bg-[color-mix(in_oklch,var(--accent)_85%,black)]"
									: "bg-accent-tint text-accent border-[color-mix(in_oklch,var(--accent)_25%,transparent)] hover:bg-[color-mix(in_oklch,var(--accent-tint)_70%,var(--paper))]"
							}`}
						>
							<SparkleIcon
								size={13}
								weight="fill"
								className={isAgentPanelOpen ? "text-paper" : "text-accent"}
							/>
							Ask co-pilot
						</button>
					</div>
				</header>

				{/* Main + optional right panel share a flex row so the in-flow
				    panel (xl+) shrinks the children's column instead of overlaying.
				    Below xl the slot renders a slide-over that owns its own
				    positioning and doesn't push the main column. */}
				<div className="flex-1 flex min-h-0 overflow-hidden">
					<main className="flex-1 min-w-0 overflow-y-auto flex flex-col">
						{/* Breadcrumb shows org → mailbox → section context.
						    Hidden at "/" since the org root is implied. */}
						<Breadcrumb />
						<div className="flex-1 min-h-0">{children}</div>
					</main>
					{rightPanel ? (
						<AgentPanelSlot rightPanel={rightPanel} />
					) : !mailboxId ? (
						// Org-scope fallback (#198). Mailbox routes always pass
						// `rightPanel`; if a future Shell caller on a mailbox
						// route forgets to, we don't accidentally mount the
						// org panel against per-mailbox context.
						<AgentPanelSlot rightPanel={<OrgAgentPanel />} />
					) : null}
				</div>
			</div>
		</div>
	);
}
