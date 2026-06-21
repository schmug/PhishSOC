// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

// Passkey enrollment client flow (issue #376). First key is a single create
// ceremony behind an interactive Access session. Adding a 2nd+ key first
// requires an existing-key assertion — the server's register/options returns
// `requiresStepUp` with an authentication challenge, which we satisfy before
// re-requesting the registration options. Enrollment is never agent-reachable.

import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import api from "~/services/api";
import { humanizeWebAuthnError } from "~/lib/webauthn-errors";

export async function enrollPasskey(): Promise<{ firstKey: boolean }> {
	let resp = await api.webauthnRegisterOptions();

	// Adding a 2nd+ key: prove possession of an existing key first.
	if (resp.requiresStepUp) {
		if (!resp.authentication) {
			throw new Error("Enrollment step-up is unavailable. Please try again.");
		}
		let assertion;
		try {
			assertion = await startAuthentication({ optionsJSON: resp.authentication });
		} catch (err) {
			throw new Error(humanizeWebAuthnError(err));
		}
		resp = await api.webauthnRegisterOptions({ stepUpAssertion: assertion });
	}

	if (!resp.registration) {
		throw new Error("Could not start passkey enrollment. Please try again.");
	}

	let attestation;
	try {
		attestation = await startRegistration({ optionsJSON: resp.registration });
	} catch (err) {
		throw new Error(humanizeWebAuthnError(err));
	}

	const result = await api.webauthnRegisterVerify(attestation);
	return { firstKey: result.firstKey };
}
