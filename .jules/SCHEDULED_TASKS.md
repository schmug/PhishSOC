⚡ Bolt: getSnippetText memoization

## Optimize toLocaleString in Render Cycles (2026-07-28)
Prompt: Find and implement ONE small performance improvement that makes the application measurably faster or more efficient.
Action: Replaced `new Date().toLocaleString()` with a cached `formatStandardDate` in `shared/dates.ts` across `app/components/HubInviteModal.tsx` and `app/components/SidecarSettingsCard.tsx` to avoid creating a new `Intl.DateTimeFormat` instance on every render cycle.
