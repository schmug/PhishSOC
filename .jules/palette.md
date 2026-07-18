## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.

## $(date +%Y-%m-%d) - Prevent Accidental Data Loss with Confirmation Dialogs
**Learning:** Destructive UI actions such as removing members or groups from an ACL should be preceded by a confirmation dialog to prevent accidental clicks. Using native `window.confirm()` provides a lightweight, accessible, and simple way to pause the execution and ask the user for verification.
**Action:** Always wrap the execution of destructive mutations (e.g., delete, remove, transfer ownership) inside a conditional `window.confirm()` block unless a custom confirmation modal is already provided.
