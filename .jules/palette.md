## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.

## 2025-02-18 - Acl Members Panel Destructive Action Confirmation
**Learning:** Removing members or groups from an ACL is a destructive action that can lead to unintended access loss. Using a simple native `window.confirm` is an effective, accessible way to prevent accidental clicks on "Remove" buttons without the heavy overhead of implementing custom modal dialogs.
**Action:** Always wrap destructive UI actions (like removing access or deleting items) in a confirmation step such as `window.confirm`.
