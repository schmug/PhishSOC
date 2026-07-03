// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Loader } from "@cloudflare/kumo";
import { PlugsIcon, RobotIcon } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import MCPPanel from "./MCPPanel";

function LazyAgentPanel() {
	const [AgentChat, setAgentChat] = useState<React.ComponentType | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);

	useEffect(() => {
		import("~/components/AgentPanel")
			.then((mod) => {
				setAgentChat(() => mod.default);
			})
			.catch((err) => {
				console.error("Failed to load AgentPanel:", err);
				setLoadError("Failed to load agent panel");
			});
	}, []);

	if (loadError) {
		return (
			<div className="flex items-center justify-center h-full">
				<span className="text-xs text-danger">{loadError}</span>
			</div>
		);
	}
	if (!AgentChat) {
		return (
			<div className="flex flex-col items-center justify-center h-full gap-2">
				<Loader size="base" />
				<span className="text-xs text-ink-3">Loading agent...</span>
			</div>
		);
	}
	return <AgentChat />;
}

export default function AgentSidebar() {
	const [activeTab, setActiveTab] = useState<"agent" | "mcp">("agent");

	return (
		<div className="flex flex-col h-full">
			{/* Tab bar */}
			<div
				className="flex items-center border-b border-line shrink-0"
				role="tablist"
				aria-label="Agent tools"
				onKeyDown={(e) => {
					if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
						e.preventDefault();
						const tabs = ["agent", "mcp"] as const;
						const idx = tabs.indexOf(activeTab);
						const nextIdx =
							e.key === "ArrowRight" ? (idx + 1) % 2 : (idx - 1 + 2) % 2;
						setActiveTab(tabs[nextIdx]);
						document.getElementById(`${tabs[nextIdx]}-tab`)?.focus();
					}
				}}
			>
				<button
					type="button"
					role="tab"
					aria-selected={activeTab === "agent"}
					aria-controls="agent-tab-panel"
					id="agent-tab"
					tabIndex={activeTab === "agent" ? 0 : -1}
					onClick={() => setActiveTab("agent")}
					className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 bg-transparent cursor-pointer ${
						activeTab === "agent"
							? "border-accent text-ink"
							: "border-transparent text-ink-3 hover:text-ink"
					}`}
				>
					<RobotIcon
						size={14}
						weight={activeTab === "agent" ? "fill" : "regular"}
					/>
					Agent
				</button>
				<button
					type="button"
					role="tab"
					aria-selected={activeTab === "mcp"}
					aria-controls="mcp-tab-panel"
					id="mcp-tab"
					tabIndex={activeTab === "mcp" ? 0 : -1}
					onClick={() => setActiveTab("mcp")}
					className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 bg-transparent cursor-pointer ${
						activeTab === "mcp"
							? "border-accent text-ink"
							: "border-transparent text-ink-3 hover:text-ink"
					}`}
				>
					<PlugsIcon
						size={14}
						weight={activeTab === "mcp" ? "fill" : "regular"}
					/>
					MCP
				</button>
			</div>

			{/* Tab content — keep agent mounted so chat isn't lost */}
			<div className="flex-1 min-h-0 overflow-hidden">
				<div
					id="agent-tab-panel"
					role="tabpanel"
					aria-labelledby="agent-tab"
					className={activeTab === "agent" ? "h-full" : "hidden"}
					tabIndex={activeTab === "agent" ? 0 : undefined}
				>
					<LazyAgentPanel />
				</div>
				<div
					id="mcp-tab-panel"
					role="tabpanel"
					aria-labelledby="mcp-tab"
					className={activeTab === "mcp" ? "h-full" : "hidden"}
					tabIndex={activeTab === "mcp" ? 0 : undefined}
				>
					{activeTab === "mcp" && <MCPPanel />}
				</div>
			</div>
		</div>
	);
}
