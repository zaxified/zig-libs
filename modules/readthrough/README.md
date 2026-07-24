# readthrough

Backend-agnostic read-through cache coordinator — serve from cache, or on a
miss coalesce concurrent fetches (single-flight) into one backend call, store
with TTL, and invalidate explicitly. The read-path counterpart to `writebehind`.

**Status:** gap (placeholder — implementation pending).
