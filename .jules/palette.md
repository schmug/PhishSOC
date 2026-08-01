## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.
## 2025-02-18 - Native dialog verification in Playwright
**Learning:** Native browser dialogs like `window.confirm` do not render in Playwright DOM screenshots, making visual verification impossible.
**Action:** When working on native dialog enhancements, verify the behavior programmatically in testing scripts via `page.on("dialog")` rather than trying to capture screenshots of the dialog.

## 2025-02-18 - Destructive Action Protection
**Learning:** Destructive actions across the app (like ACL removals or ownership transfers) often lack native browser confirmation loops, allowing for accidental data access changes.
**Action:** Consistently intercept these operations at the event handler (e.g., `handleRemove`) with a simple synchronous `window.confirm` prior to allowing the async mutation to proceed.
