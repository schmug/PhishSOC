## 2026-05-18 - Optimization Check\n**Learning:** Found an opportunity to optimize `getSnippetText` which repeatedly calls `htmlToText` inside loops in components like `EmailListRoute` (`app/routes/email-list.tsx`). Also noted that React memoization is generally unused, and standard loop rendering could benefit from basic `React.memo` or separating pure components, but `getSnippetText` within `emails.map` is a more tangible CPU bottleneck for parsing HTML on every render.\n**Action:** Will memoize `getSnippetText` or use it as the target for performance optimization.

## 2026-05-22 - Optimize Date Formatting with Intl.DateTimeFormat
**Learning:** `Date.prototype.toLocaleDateString()` and similar methods are highly inefficient when called repeatedly inside rendering loops (like mapping over a large list of emails) because they implicitly recreate an `Intl.DateTimeFormat` instance on every call. Benchmarks showed creating and calling them repeatedly was over 100x slower than reusing an instance.
**Action:** Replaced `.toLocaleDateString()`, `.toLocaleTimeString()`, and `.toLocaleString()` calls in `shared/dates.ts` with cached, module-level `Intl.DateTimeFormat` instances to significantly reduce rendering overhead for email list views.
## 2026-05-24 - Optimize Search Highlight Parsing
**Learning:** `highlightTerms` repeatedly recompiles `RegExp` objects and executes string replacements on every single render iteration across search results, causing UI jank on larger search result batches.
**Action:** Implemented a bounded `Map` cache (size 100) to memoize the string parsing and `RegExp` instantiation inside `highlightTerms`. This resulted in a ~15x speedup for the function on synthetic benchmarks.
## 2026-05-27 - Optimize Participant Parsing
**Learning:** `formatParticipants` repeated `split()`, `map()`, and `filter()` on strings repeatedly for each row item during list view rendering. This becomes computationally expensive as the size of the list increases, especially when parsing identical threads.
**Action:** Implemented a bounded `Map` cache inside `formatParticipants` in `app/lib/utils.ts` to memoize the parsed result for unique participant lists.
