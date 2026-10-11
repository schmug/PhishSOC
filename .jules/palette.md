## 2025-02-18 - Tab Accessibility on Verdict-mix Window
**Learning:** Even small custom UI elements like inline tab switchers need full ARIA attributes (`role`, `aria-selected`, `aria-controls`, `aria-labelledby`, `tabIndex`) and keyboard navigation support (`ArrowLeft`/`ArrowRight` handlers and `focus()`) to ensure screen reader users and keyboard power users can interact with them properly.
**Action:** Always implement full ARIA mappings and `onKeyDown` navigation handlers when creating `role="tablist"` and `role="tab"` components.

## 2026-07-10 - Tab Accessibility on Status Filters
**Learning:** Segemented controls that function as tabs to swap out lists or views (like the Cases filter bar) need the standard W3C ARIA tab pattern applied: `role="tablist"` on the container, `role="tab"`, `aria-selected`, `aria-controls` on the buttons, and a roving `tabIndex`. Additionally, keyboard event handlers (`onKeyDown`) for `ArrowRight`/`ArrowLeft` must be implemented to allow keyboard-only navigation.
**Action:** When implementing visual tabs/segmented controls in React Router routes, always build them with the full ARIA suite and roving tabindex, instead of plain buttons.
