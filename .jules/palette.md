## 2026-05-21 - Add aria-expanded and aria-controls to collapsibles
**Learning:** Collapsible regions (like the thread message or security verdict panels) in this application were missing ARIA roles for screen reader state mapping. The buttons needed `aria-expanded` and `aria-controls`.
**Action:** When implementing or modifying expand/collapse UI patterns, ensure that toggle buttons are wired up with `aria-expanded` representing the boolean state, and `aria-controls` correctly tied to an explicit `id` on the content wrapper.
## 2026-06-18 - Missing aria-controls on dynamic fragment wrappers
**Learning:** React fragments (`<>...</>`) cannot accept DOM attributes, making it impossible to attach an `id` for `aria-controls`. The folder list in `Shell.tsx` had `aria-expanded` on the toggle button but lacked `aria-controls` because the expanded content was wrapped in a fragment.
**Action:** Always verify that conditionally expanded content is wrapped in an actual DOM element (like `<div>`) with a unique `id` so that `aria-controls` on the toggle button can correctly point to it.
## 2026-06-25 - Add aria-controls for mobile menu toggle
**Learning:** The mobile hamburger menu toggle inside `Shell.tsx` correctly used `aria-expanded` but lacked an `aria-controls` attribute linking it to the actual menu container, breaking the complete ARIA contract for collapsible menus.
**Action:** Always verify that buttons toggling a panel/menu not only use `aria-expanded` but also have `aria-controls` pointing to a unique `id` on the container that is being toggled.
