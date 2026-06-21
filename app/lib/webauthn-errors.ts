// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Map a WebAuthn ceremony failure (DOMException name) to a user-presentable
// message, shared by the step-up assertion and the enrollment flows (#376).
export function humanizeWebAuthnError(err: unknown): string {
	const name = err instanceof Error ? err.name : "";
	switch (name) {
		case "NotAllowedError":
			return "The request was cancelled or timed out. Please try again.";
		case "InvalidStateError":
			return "This authenticator is already registered for your account.";
		case "SecurityError":
			return "WebAuthn could not run on this origin. Contact your administrator.";
		default: {
			const message = err instanceof Error ? err.message : "";
			return message || "Passkey operation failed.";
		}
	}
}
