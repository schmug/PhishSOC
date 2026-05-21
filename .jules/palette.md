## 2026-05-21 - Add aria-expanded and aria-controls to collapsibles
**Learning:** Collapsible regions (like the thread message or security verdict panels) in this application were missing ARIA roles for screen reader state mapping. The buttons needed `aria-expanded` and `aria-controls`.
**Action:** When implementing or modifying expand/collapse UI patterns, ensure that toggle buttons are wired up with `aria-expanded` representing the boolean state, and `aria-controls` correctly tied to an explicit `id` on the content wrapper.
