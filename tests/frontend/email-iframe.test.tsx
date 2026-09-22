// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Frontend tests for EmailIframe plain-text body rendering (issue #708).
 *
 * Acceptance:
 * - A plain-text body (no HTML tags) is escaped and wrapped so `white-space:
 *   pre-wrap` preserves its line/paragraph structure instead of collapsing
 *   to one line.
 * - `<`, `>`, `&` in a plain-text body render literally (escaped, not dropped).
 * - A genuine HTML body is sanitized unmodified — identical output before and
 *   after the fix.
 */

import { render, waitFor } from "@testing-library/react";
import DOMPurify from "dompurify";
import { describe, expect, it } from "vitest";
import EmailIframe from "~/components/EmailIframe";

async function getSrcdoc(container: HTMLElement): Promise<string> {
	const iframe = container.querySelector("iframe");
	if (!iframe) throw new Error("iframe not rendered");
	await waitFor(() => expect(iframe.srcdoc).not.toBe(""));
	return iframe.srcdoc;
}

describe("EmailIframe — plain-text body rendering (issue #708)", () => {
	it("wraps a plain-text body with newlines in a white-space: pre-wrap container", async () => {
		const { container } = render(
			<EmailIframe body={"line one\n\nline two\n- bullet a\n- bullet b"} />,
		);
		const srcdoc = await getSrcdoc(container);

		expect(srcdoc).toContain("white-space: pre-wrap");
		// The raw newlines must survive into the injected body (not collapsed).
		expect(srcdoc).toContain("line one\n\nline two\n- bullet a\n- bullet b");
	});

	it("escapes <, > and & in a plain-text body instead of dropping them", async () => {
		const { container } = render(
			<EmailIframe body={"Rates: 3 < 5 > 2, terms & conditions apply"} />,
		);
		const srcdoc = await getSrcdoc(container);

		expect(srcdoc).toContain("Rates: 3 &lt; 5 &gt; 2, terms &amp; conditions apply");
	});

	it("renders a genuine HTML body identically to plain DOMPurify.sanitize with the same config", async () => {
		const htmlBody = "<p>Hello <b>world</b></p><a href=\"https://example.com\">link</a>";
		const { container } = render(<EmailIframe body={htmlBody} />);
		const srcdoc = await getSrcdoc(container);

		const expectedClean = DOMPurify.sanitize(htmlBody, {
			USE_PROFILES: { html: true },
			FORBID_TAGS: ["style"],
			ADD_ATTR: ["target"],
			FORCE_BODY: true,
		});

		expect(srcdoc).toContain(expectedClean);
		// No pre-wrap wrapper is introduced for genuine HTML bodies.
		expect(srcdoc).not.toContain("white-space: pre-wrap");
	});
});
