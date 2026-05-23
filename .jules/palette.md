## 2024-05-23 - Screen Reader Accessibility for Collapsible Panels
**Learning:** Collapsible panels across the email UI (like SecurityVerdictPanel and ThreadMessage) were missing `aria-expanded` attributes, meaning screen reader users wouldn't know if these interactive elements were toggling content or what their current state was.
**Action:** Added `aria-expanded={expanded}` to toggle buttons to correctly communicate state to assistive technologies. Will ensure future custom collapsible components always include this attribute.
