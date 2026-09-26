// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import EmailListRow from "~/components/EmailListRow";
import type { Email } from "~/types";
import { renderWithProviders } from "./test-utils";

const EMAIL: Email = {
	id: "e1",
	subject: "Quarterly numbers",
	sender: "cfo@vendor.test",
	recipient: "ops@a.test",
	date: "2026-09-01T12:00:00.000Z",
	read: false,
	starred: false,
	snippet: "See attached",
	thread_count: 1,
};

function renderRow(extra: Partial<Parameters<typeof EmailListRow>[0]> = {}) {
	const handlers = { onOpen: vi.fn(), onToggleStar: vi.fn(), onToggleRead: vi.fn(), onDelete: vi.fn() };
	renderWithProviders(<EmailListRow email={EMAIL} isSelected={false} compact={false} {...handlers} {...extra} />);
	return handlers;
}

describe("EmailListRow", () => {
	it("renders the mailbox chip only when mailboxLabel is given", () => {
		renderRow({ mailboxLabel: "ops@a.test" });
		expect(screen.getByTestId("row-mailbox")).toHaveTextContent("ops@a.test");
	});

	it("omits the chip on per-mailbox pages", () => {
		renderRow();
		expect(screen.queryByTestId("row-mailbox")).toBeNull();
	});

	it("routes clicks to the right handler without opening the row", async () => {
		const user = userEvent.setup();
		const h = renderRow();
		await user.click(screen.getByRole("button", { name: /star message/i }));
		expect(h.onToggleStar).toHaveBeenCalledTimes(1);
		expect(h.onOpen).not.toHaveBeenCalled();
		await user.click(screen.getByText("Quarterly numbers"));
		expect(h.onOpen).toHaveBeenCalledTimes(1);
	});
});
