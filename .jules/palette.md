## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.
## 2026-07-17 - Safe Destructive Actions
**Learning:** Destructive UI actions (e.g., removing ACL members/groups, deleting emails, clearing chat history) in the Kumo UI system should always be preceded by a confirmation dialog to prevent accidental data loss. Small touches like `window.confirm()` and wrapping icon-only action buttons in `<Tooltip>` significantly improve UX safety and accessibility.
**Action:** When implementing new panels or features with deletion capabilities, always include a `window.confirm` check or equivalent confirmation state before firing mutation requests.
