// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { IntelFeed, MailboxSettings } from "../../shared/mailbox-settings";

describe("MailboxSettings", () => {
  // Post-#106: schema-layer defaults are deliberately gone. The resolver in
  // workers/lib/mailbox-settings.ts applies system defaults as the bottom
  // of the inheritance stack — putting them on the schema would make every
  // read look like an override (mailbox JSON would round-trip with the
  // default materialised, indistinguishable from "the user picked this
  // value" once written back). See tests/lib/resolve-mailbox-settings.test.ts
  // for default-application coverage.
  it("leaves autoDraft undefined when missing (default lives in resolver)", () => {
    const parsed = MailboxSettings.parse({});
    expect(parsed.autoDraft).toBeUndefined();
  });

  it("leaves agentModel undefined when missing (default lives in resolver)", () => {
    const parsed = MailboxSettings.parse({});
    expect(parsed.agentModel).toBeUndefined();
  });

  it("respects an explicit disabled autoDraft", () => {
    const parsed = MailboxSettings.parse({ autoDraft: { enabled: false } });
    expect(parsed.autoDraft?.enabled).toBe(false);
  });

  it("preserves arbitrary extra fields (passthrough)", () => {
    const parsed = MailboxSettings.parse({ agentSystemPrompt: "Hi" });
    expect(parsed.agentSystemPrompt).toBe("Hi");
  });

  // #151 PR A: the three security-critical model fields are back on
  // MailboxSettings as per-mailbox overrides, with UI guardrails (curated
  // dropdown + confirmation modal). The resolver chain is mailbox > org >
  // default; domain tier is excluded (same risk without guardrails).
  it("declares injectionScannerModel / draftVerifierModel / classifierModel as optional strings", () => {
    // Fields round-trip as typed strings when set.
    const parsed = MailboxSettings.parse({
      injectionScannerModel: "@cf/meta/llama-3.1-8b-instruct-fast",
      draftVerifierModel: "@cf/meta/llama-4-scout-17b-16e-instruct",
      classifierModel: "@cf/meta/llama-3.1-8b-instruct-fast",
    });
    expect(parsed.injectionScannerModel).toBe("@cf/meta/llama-3.1-8b-instruct-fast");
    expect(parsed.draftVerifierModel).toBe("@cf/meta/llama-4-scout-17b-16e-instruct");
    expect(parsed.classifierModel).toBe("@cf/meta/llama-3.1-8b-instruct-fast");
    // Absent = inherit (not defaulted at schema layer — resolver fills in defaults).
    const empty = MailboxSettings.parse({});
    expect(empty.injectionScannerModel).toBeUndefined();
    expect(empty.draftVerifierModel).toBeUndefined();
    expect(empty.classifierModel).toBeUndefined();
  });

  it("rejects a non-string injectionScannerModel", () => {
    const result = MailboxSettings.safeParse({ injectionScannerModel: 42 });
    expect(result.success).toBe(false);
  });

  // The security sub-shape is opt-in: an undefined `security` block must
  // round-trip to undefined (no surprise object materialised). The runtime
  // consumer in `workers/security/settings.ts` is the single source of
  // default values — we don't want the schema to invent a default that the
  // consumer would then overwrite.
  it("leaves security undefined when missing", () => {
    const parsed = MailboxSettings.parse({});
    expect((parsed as { security?: unknown }).security).toBeUndefined();
  });

  it("accepts a valid attachment_policy", () => {
    const parsed = MailboxSettings.parse({
      security: {
        attachment_policy: {
          executable_action: "block",
          container_action: "score",
          macro_office_action: "ignore",
          custom_blocklist_extensions: ["dmg", "rtf"],
        },
      },
    });
    expect(parsed.security?.attachment_policy?.executable_action).toBe("block");
    expect(parsed.security?.attachment_policy?.custom_blocklist_extensions).toEqual(["dmg", "rtf"]);
  });

  it("rejects an invalid attachment action enum", () => {
    const result = MailboxSettings.safeParse({
      security: {
        attachment_policy: { executable_action: "lol" },
      },
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      // Issue should point at the bad enum value, not surface a generic 500.
      const path = result.error.issues[0].path.join(".");
      expect(path).toContain("executable_action");
    }
  });

  it("preserves co-existing security fields (allowlist alongside attachment_policy)", () => {
    // Regression guard for the passthrough hazard: adding a typed `security`
    // sub-shape must NOT strip unrelated security fields like
    // `allowlist_senders` or `thresholds` — they live in passthrough.
    const parsed = MailboxSettings.parse({
      security: {
        allowlist_senders: ["ceo@company.com"],
        thresholds: { tag: 30, quarantine: 60, block: 80 },
        attachment_policy: { executable_action: "score" },
      },
    });
    const sec = parsed.security as Record<string, unknown>;
    expect(sec.allowlist_senders).toEqual(["ceo@company.com"]);
    expect(sec.thresholds).toEqual({ tag: 30, quarantine: 60, block: 80 });
  });

  it("accepts folder_policies with mode + treat_as_verified", () => {
    const parsed = MailboxSettings.parse({
      security: {
        folder_policies: {
          inbox: { treat_as_verified: true },
          archive: { mode: "skip_classifier" },
          quarantine: { mode: "skip_all" },
        },
      },
    });
    expect(parsed.security?.folder_policies?.inbox?.treat_as_verified).toBe(true);
    expect(parsed.security?.folder_policies?.archive?.mode).toBe("skip_classifier");
    expect(parsed.security?.folder_policies?.quarantine?.mode).toBe("skip_all");
  });

  it("allows unknown folder names in folder_policies (forward-compatible)", () => {
    // User-defined custom folders must survive the round-trip — folder ids
    // are runtime data, not a closed enum.
    const result = MailboxSettings.safeParse({
      security: {
        folder_policies: {
          "Newsletters/2026": { mode: "skip_classifier" },
        },
      },
    });
    expect(result.success).toBe(true);
  });

  it("rejects an invalid folder mode value", () => {
    const result = MailboxSettings.safeParse({
      security: {
        folder_policies: { inbox: { mode: "burn_it_down" } },
      },
    });
    expect(result.success).toBe(false);
  });

  // classification.skip_on_timeout — issue #28 narrowed Rule 5. Optional, no
  // schema-level default; the runtime consumer in `workers/security/settings.ts`
  // owns the default value (true).
  it("round-trips classification.skip_on_timeout=false", () => {
    const parsed = MailboxSettings.parse({
      security: { classification: { skip_on_timeout: false } },
    });
    expect(parsed.security?.classification?.skip_on_timeout).toBe(false);
  });

  it("leaves classification undefined when missing", () => {
    const parsed = MailboxSettings.parse({});
    expect(parsed.security?.classification).toBeUndefined();
  });

  it("rejects a non-boolean skip_on_timeout", () => {
    const result = MailboxSettings.safeParse({
      security: { classification: { skip_on_timeout: "yes" } },
    });
    expect(result.success).toBe(false);
  });
});

describe("IntelFeed schema — auth_secret FEED_SECRET_ prefix (#418)", () => {
  it("rejects a non-FEED_SECRET_ auth_secret at parse time", () => {
    const result = IntelFeed.safeParse({ id: "feed-1", auth_secret: "MASTER_DB_PASSWORD" });
    expect(result.success).toBe(false);
  });

  it("accepts an absent auth_secret (optional — no Authorization header sent)", () => {
    const result = IntelFeed.safeParse({ id: "feed-1" });
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.auth_secret).toBeUndefined();
  });

  it("accepts a valid FEED_SECRET_* auth_secret", () => {
    const result = IntelFeed.safeParse({ id: "feed-1", auth_secret: "FEED_SECRET_THREATFOX" });
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.auth_secret).toBe("FEED_SECRET_THREATFOX");
  });

  it("rejects a non-FEED_SECRET_ auth_secret nested via MailboxSettings.intel.feeds", () => {
    const result = MailboxSettings.safeParse({
      intel: { feeds: [{ id: "feed-1", auth_secret: "MASTER_DB_PASSWORD" }] },
    });
    expect(result.success).toBe(false);
  });

  it("accepts a valid FEED_SECRET_* value nested via MailboxSettings.intel.feeds", () => {
    const result = MailboxSettings.safeParse({
      intel: { feeds: [{ id: "feed-1", auth_secret: "FEED_SECRET_OPENPHISH" }] },
    });
    expect(result.success).toBe(true);
  });
});
