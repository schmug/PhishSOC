## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.

## 2025-02-18 - AclMembersPanel Destructive Action Confirmation
**Learning:** Adding `window.confirm` to destructive UI actions (like removing ACL members/groups) improves UX safety by preventing accidental data loss, and wrapping icon-only buttons with `<Tooltip>` improves accessibility for mouse/sighted users.
**Action:** Always add confirmation dialogs and tooltips to destructive icon-only actions in custom UI components.
