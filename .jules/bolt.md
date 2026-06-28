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
## 2026-05-29 - Optimize Thread Message Plain Text Extraction
**Learning:** `stripHtml` calls `htmlToPlainText` which parses HTML via a character-walking tokenizer. This occurs repeatedly during every re-render of thread rows in `ThreadMessage.tsx` (via `stripHtml(email.body || "").slice(0, 80)`). For threads with large or complex HTML bodies, this CPU-intensive re-parsing on every UI update loop can cause noticeable jank.
**Action:** Implemented a bounded `Map` cache (size 1000) inside `stripHtml` in `app/lib/utils.ts` to memoize the plain text extraction for identical HTML strings, mirroring the existing optimization pattern used for `getSnippetText` and `formatParticipants`. This effectively eliminates redundant HTML parsing overhead during thread view rendering.
## 2026-06-06 - Optimize Date Handling in Render Loops
**Learning:** Instantiating `new Date` or calling `.toLocaleString()` inside loops and array sorting methods causes significant object allocation and CPU overhead. Benchmarks showed `Intl.DateTimeFormat` instantiation and `new Date` instantiation are much slower than `Date.parse()` and cached formatters.
**Action:** Use `Date.parse()` for timestamp comparisons and cache `Intl.DateTimeFormat` instances module-globally rather than recreating them inside component render loops.
## 2026-06-06 - Optimize Intl.DateTimeFormat Instantiations by Timezone
**Learning:** Instantiating `Intl.DateTimeFormat` instances inside functions like `localDateParts` which are called repeatedly during time rule evaluations incurs significant performance overhead. Micro-benchmarks demonstrate that creating a new `Intl.DateTimeFormat` instance repeatedly takes hundreds of milliseconds, while fetching a pre-instantiated, cached version from a Map takes barely anything.
**Action:** Replaced repetitive instantiations of `Intl.DateTimeFormat` in `workers/security/time-rules.ts` with a module-level `Map` cache (`FORMATTER_CACHE`) keyed by `timezone`. This drastically speeds up business-hours calculations, reducing overhead by ~36x for repeated calls.
## 2026-06-28 - Avoid Unnecessary Date Object Allocation
**Learning:** Instantiating `new Date` to get a timestamp via `.getTime()` inside hot paths causes unnecessary object allocation and garbage collection overhead.
**Action:** Replace `new Date(string).getTime()` with `Date.parse(string)` for pure timestamp parsing.
