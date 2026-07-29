## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.
## 2025-02-18 - Native Confirm Dialog Verification in Playwright
**Learning:** Native browser dialogs (like `window.confirm()`) are not rendered in the DOM and will not appear in captured images when taking screenshots with Playwright.
**Action:** When using Playwright to verify UI changes involving native dialogs, use event listeners like `page.on('dialog', ...)` in your test script to programmatically capture the dialog's message and verify its intended behavior rather than relying solely on visual screenshots.
