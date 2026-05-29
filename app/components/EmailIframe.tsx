// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import DOMPurify from "dompurify";
import { useCallback, useEffect, useRef, useState } from "react";
import { useUIStore } from "~/hooks/useUIStore";

interface EmailIframeProps {
	body: string;
	/** When true, iframe auto-sizes to content height instead of filling parent */
	autoSize?: boolean;
	/** Called when the analyst clicks a link inside the rendered email body.
	 *  The iframe never navigates; the parent decides what to show instead. */
	onLinkClick?: (href: string) => void;
}

// Email-body design system, intentionally distinct from the app tokens because
// the PhishSOC oklch tokens are not reachable past the CSP boundary inside the
// sandboxed iframe. Hex values approximate the corresponding `--paper` /
// `--ink` tokens for each theme so unstyled email bodies blend with the chrome.
const EMAIL_PALETTES = {
	light: {
		bg: "#ffffff",
		text: "#1a1a1a",
		link: "#2563eb",
		quoteBorder: "#d1d5db",
		quoteText: "#6b7280",
		preBg: "#f3f4f6",
	},
	dark: {
		bg: "#1a1816",
		text: "#ebe9e3",
		link: "#60a5fa",
		quoteBorder: "#3a352d",
		quoteText: "#968f80",
		preBg: "#29241e",
	},
} as const;

/**
 * Renders email HTML inside a sandboxed iframe.
 *
 * Security model:
 * - DOMPurify sanitises the HTML before injection.
 * - The iframe sandbox does NOT include `allow-same-origin`, so even if
 *   DOMPurify has a bypass the attacker's code runs in an opaque origin
 *   with no access to the parent page's cookies, DOM, or API.
 * - Because the iframe is cross-origin we cannot read `contentDocument`
 *   for auto-sizing. Instead, the injected HTML includes a tiny inline
 *   script that posts its body height to the parent via `postMessage`.
 *   The `allow-scripts` flag is required for this, but scripts inside
 *   the opaque-origin sandbox cannot access anything useful.
 * - A strict CSP meta tag blocks external resource loads inside the
 *   iframe as a defense-in-depth layer.
 */
export default function EmailIframe({ body, autoSize, onLinkClick }: EmailIframeProps) {
	const iframeRef = useRef<HTMLIFrameElement>(null);
	const [height, setHeight] = useState(autoSize ? 100 : 0);
	const theme = useUIStore((s) => s.theme);

	// Listen for messages from the sandboxed iframe (height reports + link clicks)
	const handleMessage = useCallback(
		(event: MessageEvent) => {
			// Only accept messages from our own iframe
			if (event.source !== iframeRef.current?.contentWindow) return;
			if (!event.data || typeof event.data !== "object") return;

			if (
				autoSize &&
				event.data.__emailIframeHeight &&
				typeof event.data.height === "number" &&
				event.data.height > 0
			) {
				setHeight(event.data.height);
			}

			if (
				event.data.__emailLinkClick &&
				typeof event.data.href === "string" &&
				event.data.href
			) {
				onLinkClick?.(event.data.href);
			}
		},
		[autoSize, onLinkClick],
	);

	useEffect(() => {
		window.addEventListener("message", handleMessage);
		return () => window.removeEventListener("message", handleMessage);
	}, [handleMessage]);

	useEffect(() => {
		const iframe = iframeRef.current;
		if (!iframe || !body) return;

		const cleanBody = DOMPurify.sanitize(body, {
			USE_PROFILES: { html: true },
			FORBID_TAGS: ["style"],
			ADD_ATTR: ["target"],
			FORCE_BODY: true,
		});

		const padding = autoSize ? "0" : "24px";

		// Height-reporting script: sends body.scrollHeight to the parent.
		// Runs inside the opaque-origin sandbox so it has zero access to
		// the parent page — it can only postMessage.
		const heightScript = autoSize
			? `<script>
				function reportHeight() {
					var h = document.body.scrollHeight;
					if (h > 0) parent.postMessage({ __emailIframeHeight: true, height: h }, "*");
				}
				reportHeight();
				setTimeout(reportHeight, 50);
				setTimeout(reportHeight, 150);
				setTimeout(reportHeight, 400);
			<\/script>`
			: "";

		// Link-interception script: prevents anchor navigation and posts the
		// href to the parent so it can show the safe link inspector. The
		// sandbox no longer grants allow-popups or
		// allow-top-navigation-by-user-activation, so navigation is already
		// blocked at the sandbox level — this script surfaces the clicked URL.
		const linkScript = `<script>
			document.addEventListener("click", function(e) {
				var el = e.target;
				while (el && el.tagName !== "A") el = el.parentElement;
				if (!el) return;
				e.preventDefault();
				var href = el.href;
				if (href) parent.postMessage({ __emailLinkClick: true, href: href }, "*");
			}, true);
		<\/script>`;

		// Use srcdoc so the iframe is truly sandboxed (no same-origin access).
		// We can't use doc.write() because that requires allow-same-origin.
		const palette = EMAIL_PALETTES[theme === "dark" ? "dark" : "light"];
		iframe.srcdoc = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data: cid: https:; script-src 'unsafe-inline';">
<style>
* { box-sizing: border-box; }
html {
	background: ${palette.bg};
	color-scheme: ${theme === "dark" ? "dark" : "light"};
}
body {
	font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
	font-size: 14px;
	line-height: 1.6;
	color: ${palette.text};
	background: ${palette.bg};
	padding: ${padding};
	margin: 0;
	word-wrap: break-word;
	overflow-wrap: break-word;
	${autoSize ? "overflow: hidden;" : ""}
}
[style*="position: fixed"], [style*="position:fixed"], [style*="position: absolute"], [style*="position:absolute"] {
	position: relative !important;
}
a { color: ${palette.link}; }
img { max-width: 100%; height: auto; }
blockquote {
	border-left: 3px solid ${palette.quoteBorder};
	padding-left: 1em;
	margin-left: 0;
	color: ${palette.quoteText};
}
pre {
	background: ${palette.preBg};
	padding: 12px;
	border-radius: 6px;
	overflow-x: auto;
	font-size: 13px;
}
table { border-collapse: collapse; max-width: 100%; }
td, th { padding: 4px 8px; }
p { margin: 4px 0; }
h1, h2, h3 { margin: 8px 0 4px; }
ul, ol { padding-left: 20px; margin: 4px 0; }
</style>
</head>
<body>${cleanBody}${heightScript}${linkScript}</body>
</html>`;
	}, [body, autoSize, theme]);

	return (
		<iframe
			ref={iframeRef}
			className="block w-full border-0"
			style={autoSize ? { height: `${height}px` } : { height: "100%" }}
			sandbox="allow-scripts"
			title="Email content"
		/>
	);
}
