## 2026-11-20 - Add confirmation dialogs to destructive ACL actions
**Learning:** Destructive actions like removing ACL members/groups or transferring ownership should always prompt for user confirmation to prevent accidental data loss or lockouts.
**Action:** Use native `window.confirm()` before executing mutation requests for these actions.
