# staticfiles — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-11** (3) — A1 fix campaign round 2, F5/F13/F17. BEHAVIOURAL (all three).
  - **F5 (round-2 Q8):** `ETag` is now **weak** (`W/` prefix) by default —
    `Options.strong_etag = true` reverts to the pre-fix strong form. `mtime`'s one-second
    granularity meant a same-second, same-size edit left the old strong tag unchanged despite
    RFC 9110 §8.8.1, and a strong tag authorizes `If-Range` to splice bytes from two file
    versions into one response. Weak closes that outright — `ifRangeAllows` rejects a weak
    validator, falling back to a full 200 — at the cost that `If-Range`-conditioned byte-range
    RESUME never succeeds for any client under the new default. RED (default reverted to
    always-strong): 38/41 (3 fail) → GREEN 41/41.
  - **F13 (round-2 Q5, per RFC 9110):** a single path segment over the filesystem's `NAME_MAX`
    fell into `mapOpenError`'s `else` branch → 500, read by the client as a server fault for
    input it supplied. Now → 404: no file of that name can exist, the same fact every other
    "missing name" case here already answers 404 to (RFC 9110's 414 is about a URI longer than
    THIS SERVER is willing to interpret, which the `http`-layer request-line/header budgets
    already cover one level up — not about a segment too long for the filesystem). RED: 41/42
    (1 fail) → GREEN 42/42.
  - **F17 (round-2 Q8):** a directory URL missing its trailing slash (`GET /sub`) now redirects
    301 to the canonical slash-terminated form (`Options.redirect_to_trailing_slash`, default
    true) before anything is resolved further — matching Go `net/http` `FileServer` / nginx, the
    module's own stated reference model. Without this, `/sub` and `/sub/` silently served the
    identical content under two different URLs, and any relative link/asset inside that page
    resolved against whichever one the browser's address bar showed. Query string is preserved
    across the redirect; a plain file is never redirected; `redirect_to_trailing_slash = false`
    keeps the pre-fix dual serving. RED (redirect disabled): 41/43 (2 fail) → GREEN 43/43.
  - Three existing tests that happened to request bare directory URLs
    (`serveDirectory: a listing that cannot be labelled text/html…`, `serve: directory request
    serves index.html`, `serve: a directory-listing request opens its target directory once…`)
    updated to request the canonical slash-terminated form where they were testing something
    OTHER than F17 itself.
- **2026-09-11 (2)** — A1 fix campaign round 2, F6 (cross-module with `http`, one commit —
  round-2 Q4). BEHAVIOURAL. Two related defects at the `http` compression seam, both only
  reachable when the embedding `Server` has `Options.compression` set:
  - A byte-range response (206) could still be gzip-compressed: `Content-Range` describes
    offsets into the IDENTITY body, and the wire body was the gzip bytes of that range —
    a client or intermediary reassembling ranges would write compressed bytes at identity
    offsets. Fixed in `http` (`ResponseWriter.shouldCompress` now excludes 206
    unconditionally), not here — `staticfiles` has no way to know whether `http` is about
    to compress a response it hands back.
  - The identity and gzip representations of the same file shared one strong `ETag`
    (`buildETag`'s `size+mtime`), when RFC 9110 §8.8.3 requires a validator that
    distinguishes representations. Fixed in `http`: a strong `ETag` on a response `http`
    is about to gzip now reaches the wire prefixed `W/` — `staticfiles`' own stored/returned
    value, and the identity-negotiated wire value, are unchanged.
  - `runRequest`'s shared test harness now wires `.compression`+a gzip scratch buffer
    (previously absent, so no staticfiles test could ever exercise compression at all);
    the standalone `sendFile`-vs-`serve` byte-identity comparison test picked up the same
    options for the same reason. Two new tests here mirror the two `http`-side ones.
  - RED (both `http`-side mechanisms disabled): 38 pass / 2 fail / 40 → GREEN 40/40.
- **2026-09-11** — **NO CONSUMER-VISIBLE CHANGE:** a directory-listing request
  (no index file, `directory_listing = true`) now resolves its target
  directory once instead of twice (A1 F11 — the old `serve`/`serveDirectory`
  split re-walked the whole path from the root a second time via a now-removed
  `openDirWithinRoot`, a TOCTOU shape plus a doubled `openat` cost). The
  public `resolveFile`/`openWithinRoot` contract, and every observable
  status/body, is unchanged.
- **2026-09-10** — A1 audit fix campaign (`staticfiles` has zero in-repo consumers, so input
  hardening/tightening needed no sign-off; see `DECISIONS.md` P1). Three HIGH findings, all
  containment/memory-safety, plus follow-on MED/LOW test and doc gaps:
  - **F1 (HIGH):** `follow_symlinks = true` verified containment (`verifyContained`) only on
    the single-leaf-file open path — never on index lookup or directory listing. A directory
    component that was itself a symlink out of root, or a directory's own `index.html` being
    a symlink out, or a directory listing of a symlinked-out target, all served 200 with
    out-of-root content. `openIndex` now takes the scan root and runs the same containment
    check; `openDirWithinRoot` (the listing path) runs an equivalent check
    (`verifyContainedDir`) on the directory it is about to list. Default (`follow_symlinks =
    false`) was never affected.
  - **F2 (HIGH):** `Opened.mime_name` was a slice into `resolveFile`'s local scratch buffer —
    dangling the instant `resolveFile` returned, so `Content-Type` could be computed from
    freed stack (README's own documented `sendFile`-after-`resolveFile` pattern hit this
    directly). `Opened` now owns its name in a fixed `mime_name_buf` field, read via
    `mimeName()`.
  - **F3 (HIGH):** the public `openWithinRoot` ("layer 2") did not itself reject `..` —
    `openat(dirfd, "..")` is a legal syscall that neither `O_NOFOLLOW` nor `resolve_beneath`
    stops, and `Dir.OpenOptions` (unlike `OpenFileOptions`) has no `resolve_beneath` field at
    all. A caller reaching this `pub` function with an unsanitized path (exactly what it is
    documented to accept as an independent second layer) walked straight out of root. It now
    rejects `..` itself, independent of `sanitizePath`.
  - **F4/F7/F9/F12 (MED):** added the missing test coverage the audit's mutation runner
    found: a symlinked directory component under default options, `verifyContained`'s two
    clauses (sibling-prefix guard and full-length prefix, tested independently), `..` with
    `serve_dotfiles = true`, and dotfile entries in a directory listing.
  - **F16 (LOW):** a symlinked directory component under default (no-follow) options answered
    404, while a symlinked leaf file correctly answered the documented 403 — `openDir`'s own
    error didn't reliably say "refused because it's a symlink" the way `openFile`'s
    `SymLinkLoop` does. Both walk sites now fall back to a no-follow `statFile` on the failed
    component to tell the two apart.
  - **F14 (LOW):** SPEC.md claimed the per-request ETag/Last-Modified scratch lives in
    threadlocal storage the response writer borrows without copying. Backwards on both counts
    — they are plain locals, and `setHeader` copies. Corrected to match `root.zig`'s own
    "Locals, not thread-locals" comment, which was already right.
  - **F15 (LOW):** a test iterated three request paths but only asserted anything for one of
    them, and its comment claimed a 404 the code never sends for the other two (it's 403).
    Fixed both.
  - **F18 (LOW):** added `X-Content-Type-Options: nosniff` (best-effort) on every
    representation response, alongside the existing not-best-effort `Content-Type` guard.
    SPEC.md now also records that the module does not offer a way to force a download
    (`Content-Disposition`) — a deliberate Go/nginx-style trade-off, not an oversight.
  - **F10 refuted:** already fixed 2026-09-07 (commit `9d96e069`, unrelated session) —
    `fuzzSanitizePath` now draws length and bytes as one `smith.slice` call instead of length
    then bytes, so a corpus replay no longer collapses to a zero-length input every time.
  - Left open for the user (policy/API-shape decisions, not input hardening — see
    `~/CML/20260901-zig-libs-audit/A1/staticfiles.md` §"Dispozice 2026-09-10"): F5 (ETag
    strong vs. weak), F6 (gzip × 206 × ETag, spans `http` too), F13 (`NameTooLong` → 404 vs.
    414), F17 (redirect bare directory requests to the trailing-slash form). Deferred as
    excessive engineering risk for this pass: F8 (a FIFO fixture risks the same indefinite
    hang the audit itself avoided), F11 (the directory-listing path re-walks from root a
    second time; fixing it means threading an already-open `Dir` through the `IsDir` error
    path, a real internal-API change).

- **2026-09-07** — Test-only, no production change: `fuzzSanitizePath`'s own comment said
  "Length drawn BEFORE the bytes it bounds: every mutated byte the fuzzer spends then lands
  inside the slice", and that was not true when it was written. A ranged `Smith` draw
  returns the range MINIMUM unless a whole eight-octet word already lies inside the range,
  so `raw_len` was **0** on every input the ordinary lane ever ran: `smith.bytes` got a
  zero-length slice and `sanitizePath` was called on `""` every round. The traversal-safety
  contract this harness exists to check had never been evaluated on a path. It now draws
  with one `smith.slice(&raw_buf)`, and carries a corpus: the clean paths and every
  traversal/injection vector the value tests above pin (encoded `../`, encoded backslash,
  NUL truncation, truncated percent), each with the `u64` word `allow_dotfiles` reads -
  without which that knob is dead on a corpus replay and the `allow_dotfiles = true` half,
  which is a different contract, would never run. Measured by the new `corpus:` guard: 19
  non-empty seeds, 10 accepted, **14 path segments walked**, and 2 seeds under
  `allow_dotfiles`. Segments rather than acceptance, because `sanitizePath("")` succeeds -
  the empty path is the root - so an acceptance count reads as a pass over a corpus that
  reached nothing.

- **2026-08-18** — `Handler.sendFile` is now `pub` (was `fn`, internal-only). A caller
  who already holds a resolved/opened file — e.g. it called `resolveFile` itself to
  compose an app-specific 404 page before falling back to the static handler — can
  now serve it directly (`h.sendFile(req, rw, &opened)`) instead of paying a second
  `resolveFile` inside `serve`. Ownership unchanged: `sendFile` still just borrows
  `opened` and never closes it, same as the internal call site in `serve`.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — a `304 Not Modified` that cannot
  carry its `ETag` is no longer sent as a 304. `http.conditional.apply` stages the
  304 status *before* it writes the validator, so the `catch false` on that call
  swallowed the failure with the status already staged: the measured wire was
  `304 Not Modified` carrying `Content-Type` and `Content-Length: 11` for a body a
  304 must not have, with no `ETag` for the client to revalidate with next time —
  framing that contradicts itself, and a validator-less 304 that guarantees the same
  outcome on every following request. Reachable through header-**table** exhaustion
  (32 slots), not the byte budget, which is exactly the route last entry's
  escalate-to-500 cannot rescue: once middleware has set `Content-Type`, this
  handler's own `setHeader` for it is a replace that needs no slot and succeeds.
  **What changes for a consumer:** such a request now gets the full representation —
  `200 OK` with `Content-Type`, matching `Content-Length` and the body — instead of
  the malformed 304. Declining a 304 is always conformant (RFC 9110 §15.4.5 makes it
  a SHOULD, never a MUST), so the client sees a slower but correct answer rather than
  a broken one. Deliberately *not* the 500 escalation used for `Content-Type` and
  `Cache-Control`: there, what would go out is unsafe and no correct response exists;
  here a correct, safe response exists and a 500 would throw it away to advertise a
  lost round trip. The `.proceed` arm of the same call is untouched — a lost `ETag`
  on a 200 stays best-effort, like `Last-Modified`. Nothing within the header table
  changes.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — a representation header that cannot be set
  now answers 500 instead of serving the body without it. `Content-Type` (both
  the file path and the directory index) and a configured `Cache-Control` were
  set with a bare `catch {}`, so once the response writer's 4 KiB copy store
  was spent — by middleware ahead of this handler — the file went out looking
  fine and silently unlabelled. An unlabelled body is MIME-sniffed by the
  browser, which is how an uploaded .txt or .jpg becomes stored XSS; a dropped
  `Cache-Control` puts content in a shared cache the operator meant to keep out
  of one. Both now discard the half-composed response and answer 500.
  **What changes for a consumer:** a response that used to be a 200 missing its
  Content-Type or Cache-Control is now a 500. Nothing within the budget
  changes. `Last-Modified`, `Accept-Ranges` and the 405's `Allow` stay
  best-effort and now say why at the call site: the first two cost only a
  conditional-request round trip or resumable downloads, and answering 500 in
  place of a 405 would throw away the more useful answer.
- **2026-08-06** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified against RFC 9110
  §13.1.2.
- **2026-07-22** — New module: path-traversal-safe static file handler over `http`.
