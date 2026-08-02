## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.
## 2025-02-18 - Confirmation Dialogues for Destructive Actions
**Learning:** Destructive actions like removing members/groups or transferring ownership in ACLs lack a safety net by default. Users can accidentally misclick these buttons. This was identified when reviewing the 'AclMembersPanel' component.
**Action:** Always add a `window.confirm` dialogue to functions handling destructive actions before executing the state change/API call to prevent accidental data loss or privilege changes.
