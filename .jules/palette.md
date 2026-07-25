## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.
## 2026-07-25 - Confirmation Dialogs for Destructive Actions
**Learning:** Native `window.confirm()` works excellently as a lightweight, accessible confirmation mechanism for destructive actions (like removing ACL members) without requiring complex modal state management or external components.
**Action:** When implementing new destructive UI actions (like deletes or ownership transfers), default to wrapping the mutation call in an `if (!window.confirm("...")) return;` check.
