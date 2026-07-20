## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.
## 2026-07-19 - Confirmation Dialogs for Destructive Actions
**Learning:** Native `window.confirm` is an effective, zero-dependency way to add friction to potentially destructive actions (like removing ACL members or transferring ownership) without the overhead of building custom modal dialogs.
**Action:** When working on UI components that manage critical state or permissions, always check if irreversible actions are protected by at least a simple `window.confirm` dialog.
