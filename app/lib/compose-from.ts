// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Last-used From mailbox for the /inbox composer. Per-viewer convenience only:
 * storage can be blocked or empty, so every access is guarded and callers must
 * render correctly with `null`.
 */

export const LAST_FROM_STORAGE_KEY = "phishsoc-unified-last-from";

export function readLastFrom(): string | null {
	try {
		return localStorage.getItem(LAST_FROM_STORAGE_KEY);
	} catch {
		return null;
	}
}

export function writeLastFrom(id: string): void {
	try {
		localStorage.setItem(LAST_FROM_STORAGE_KEY, id);
	} catch {
		// storage blocked — the picker still works, it just won't remember
	}
}
