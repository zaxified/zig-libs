# `http` — audit record

The dated reviews and mutation runs of this module, newest first: what was read, which mutants ran, why each
survivor is equivalent, what was found and fixed. The current score is the `**Audit:**` line of the card in
[`SPEC.md`](SPEC.md); this file is the evidence behind it. A new run adds a section at the top; old sections are
not rewritten (a later run supersedes them, it does not edit them). Runs recorded only in `CHANGELOG.md` are not
repeated here. The card's `**Audit:**` counts are cumulative over the whole-module run and the deltas after it.

## 2026-11-19 — delta mutation: wave-9 backlog batch

32 schemata mutants over the new non-test code (ReleaseSafe, one build of the module with its tests, each mutant under `setsid -w timeout` and `ulimit -v`, the whole suite per mutant): `Request.bodyOverCap` (its three conditions and the final `false`), the two `exceeded` pointers' wiring on h1 and h2, `bodyFramingFailed` (the call, each of the three arms, the status 400), `GunzipBody`'s end latch (the `done` and `failed` arms, the `failed` answer, both `ended` stores), `h2_client`'s refused-head path (the `malformed` guards in `processEvents` and `waitHead`, `fieldsValid` in the head and the trailer branch, its pseudo-field skip, the name-token, value and uppercase tests, the stored flag, `rst`, the sent RST_STREAM, `end`), and `multipart`'s part-body buffer (the buffer pointer, `seek`, `end` resets). 26 killed in the first pass; 2 more killed by tests added for the survivors (a refused stream holds none of its DATA; the `failed` answer of the latch). 3 EQUIVALENT: dropping the latch's `failed` arm and not storing `failed` at all (the second `end()` re-reads the already consumed trailer as the zero padding, which fails the CRC/ISIZE check again, and `refuseTruncated` is sticky, so every failing body fails again on every poll; the latch only stops the re-read), and `processEvents`' `if (p.malformed)` guard for a second HEADERS block on a refused stream (the block becomes `p.headers`, but `waitHead` tests `malformed` first and `deinit` frees it: nothing observable). 1 OPEN: `p.end` set by an invalid head that carries END_STREAM; the test for it (`an invalid head that carries END_STREAM is refused too`) was added after the last schemata build and is not re-run against that mutant (killed by construction: the mutant makes `ended` true). The audit found one defect, fixed in the same batch: `GunzipBody.end()` was not idempotent, so a VALID gzip request body read with `readSliceShort` (std's `readVec` swallows the first `EndOfStream` and the caller polls again) failed with `ReadFailed` and a 500 when `verify_inbound_trailer` was on (307 of 360 probe cases) -- found by the new `http-gzip-body` fuzz harness's first run. Other `Reader` wrappers checked for the same shape: `Client.Gunzip` (latched `done` / `failure`), `h1.ChunkedReader` (`.done`, sticky `fail_reason`), `ContentLengthReader` (`remaining == 0`), `RequestBody.Capped` (probe is repeatable), `multipart.Reader` (state-driven), `gzip.PaddedSource` (zeros forever): none has it.

## 2026-11-18 — delta mutation: h2 OS-thread wait parking + WINDOW_UPDATE coalescing

38 schemata mutants over the new code in `h2_server.zig` (ReleaseSafe, one build of the module with its tests, the `h2_server` tests per mutant through the kit's runner, `setsid -w timeout` 25 s, `ulimit -v`): `announce` (sequential guard, the progress bump, the wake guard forced off and on), `waitForPeer` (the io path's `Closed`, the OS path's leading and trailing `gone` checks, the deadline latch, `>=` dropped and `>`, `Stalled` as `Closed`, the timeout dropped, the futex replaced by a yield, the `parked` decrement), the connection task's drain (its announce, its `parked` registration, its futex), the hoisted `stall_ms`, `emit`'s clock restart, `grantJob` (staged ignored, the open-stream guard, `avail` forced 0, the window doubled, the reset of `unsent`, the flush), `creditConn` (the zero guard, the add, the send test forced, the window doubled, the reset), `shouldSendCredit` (all four comparisons), and the flushes after `creditConn` in `onData`, `grantJob`'s no-job path and `removeJob`. 25 killed (17 by the hang cap), 12 EQUIVALENT, 1 UNOBSERVABLE (counted with the equivalents above): cost-only — the wake forced on, `announce` in sequential mode, a `parked` left raised, the drain spinning instead of parking; redundant — the trailing `gone` check (the caller loops back to the leading one), `now > deadline` (at equality the next round, one zero-length futex wait later, stalls), `avail < 0` (at 0 the second rule's `unsent >= 0` holds), the zero guard in `creditConn` (a zero credit only re-tests the rule earlier), the doubled window at both call sites (the peer's-room rule subsumes the half-window one except at the floor, 32 767 against 32 768), the flush after a discard in `onData` (`pump` flushes after `processEvents`), `grantJob`'s no-job path (unreachable: both callers hold the job); UNOBSERVABLE — the drain's announce, needed only when a worker parks in the few instructions between `pump`'s last announce and `gone.store` (needs a scheduler hook). Tests added during the audit because the first pass left three alive: a fiber handler waiting for credit released when the connection task leaves (the io path's `Closed`), connection credit flushed by the worker while its handler keeps running (`grantJob`'s staged), and retirement credit flushed (made deterministic: in the first run it read in 4 KiB batches, so the handler could retire before every DATA frame had arrived, and the three hangs it produced were re-run after the fix: one stayed killed, two are the equivalents above). No defect.

## 2026-11-17 — delta mutation: header-copy reuse + HPACK position hints

39 schemata mutants over the new code (ReleaseSafe, one build of the whole module with its tests, each mutant under `setsid -w timeout` and `ulimit -v`, the whole suite per mutant): `putHeader`'s call into `replaceInPlace`; in `replaceInPlace` the sharing check, the tail flag (forced false and true), the fit test (`>`→`>=`, `<=`→`<`, the tail conjunct dropped, the whole test dropped), the name compare (forced different, forced equal), the name's `copiedAt` and sharing guards, the name copy, the value move, the store-end update, the stored length; `copiedAt`'s three bounds (incl. `>`→`>=`); `shared`'s self-skip, its name operand, its return, both overlap comparisons (`<`→`<=`); in the HPACK `Encoder` the `recent_len` guard, `recall`'s none/static/dynamic split, both static compares, the eviction check, both dynamic compares, `remember`'s static bound and eviction term, the hint's use, the two slot writes, the insert-fits bound and the inserted sequence. 37 killed (1 by the hang cap). 2 EQUIVALENT: `shared` checking only other entries' values, not names — no API puts another entry's NAME into a header copy (`putHeader`/`addHeader` copy their own, `setHeaderStatic`/`setHeaderBorrowed` take a comptime name), so a name never overlaps a value's copy; and skipping the `recall` hit (always running `findField`) — cost-only, the very speed-up, measured in Backlog (5 565 → 2 867 instructions per block). Tests added BEFORE the run so the first pass was strict: a respelled name adjacent to another header's copy, an empty tail copy growing in place, a same-spelling replacement over a static name, a value lent from past the store's used end (would be overwritten by the next copy), `www-authenticate: ""` (static index 61, the bound of `remember`), and the hint slot values incl. after an eviction. No defect.

## 2026-11-17 — delta mutation: `RewindableBody` and `FileSpool` (`src/rebody.zig`)

64 schemata mutants over the non-test code (a `rebody.zig`-rooted test binary in ReleaseSafe plus a ReleaseFast build for the wipes, each mutant under `setsid -w timeout` and `ulimit -v`): the fill loop's growth guard, doubling, the `limit` cap and the 256 floor, the short-read exits (`<` to `<=`), the no-spool probe, `took`'s total, `max_total` boundary and the empty-slice guard, the tap, `grow`'s copy and wipe, `deinit`'s four wipes, spool release and state resets, `len`/`spooled`, every reset in `reader()`, every branch and offset of `stream` (the `pos`/`mem_len` split, the limit, the staging refill, the latch, `got == 0`, `got > want`), and `FileSpool`'s append offset and length, `readAt`'s end and cap, its error mapping, `deinit`'s truncate, length reset, close and destroy, and `create`'s ownership. 61 killed (9 by the hang cap; the two `deinit`/`grow` memory-wipe mutants only on the ReleaseFast build, where `Allocator.free` does not poison first). 3 EQUIVALENT: `readAt` with `offset > len` instead of `>=` (the empty read at the end returns 0 either way), and the two short-read exits written as `n == 0` instead of `n < want` (a reader that returned fewer bytes than asked has ended, so the extra read returns 0 and the same return follows). Tests added BEFORE the final runs because the first pass left eight alive: a non-power-of-two `memory_limit` (the doubling overshot it), the tap never handed an empty slice, a spool opened once per body, a spool that comes up short or reports more than it was asked for (read failure, latched until the next rewind), the staging and reader buffers wiped after `deinit` and a second `deinit` releasing nothing, `readAt` over a file that already holds bytes, one `FileSpool` reused for two bodies, a file opened without read or write access, and `create`'s descriptor closing. h2 request bodies (buffered and streaming server modes) re-read identically through the same code. No defect.

## 2026-11-15 — delta mutation: `ConnSummary.timeout_phase` (gap wave)

27 schemata mutants over `ConnSummary.timeout_phase` (ReleaseSafe, one build of the
whole module with its tests, each mutant under `setsid -w timeout` and `ulimit -v`): the summary field's guard (dropped,
inverted, arms swapped), the `sum_phase` initialiser, the three `timeoutPhase` call sites (skipped, `is_h2` flipped: the
protocol-peek failure, the h2 path, the h1 path), and `timeoutPhase` itself (the write test dropped or returning another
phase, the not-timed-out guard dropped and inverted, the h2 early return dropped or returning another phase, each of
the three reader-phase arms returning another phase), plus the refactored `reportTimeout` (the `orelse return`, the
`ResponseTimeout`/`WriteTimeout` choice and its deadline test, the h2 `ReadTimeout`, the keep-alive `IdleTimeout` /
`NoRequestTimeout` choice, and the head and body error names). 25 killed. 2 are EQUIVALENT: the summary guard
`sum_end == .timed_out` dropped, and `sum_phase` initialised to `.idle` instead of null. `sum_phase` is set only by
the three sites that set `sum_end` from `connEnd`, and `timeoutPhase` is non-null exactly when `connEnd` is
`.timed_out` (both read `tr.timed_out` / `tw.timed_out`); every other exit leaves `sum_end == .refused` with the null
initial value, so the guard never changes the value. The first run also had 2 survivors that a test could reach
(`timeoutPhase` without its not-timed-out guard, and `reportTimeout` without its `orelse return`): the summary's guard
hid both, but `on_error` then reported `.timed_out` for every connection; each got a test (a connection that ends
without a deadline, closed by the server or by the client, reports no `timed_out`), and the rerun killed both.
The Audit line is cumulative: 59/60 with 1 eq + 25/27 with 2 eq.

## 2026-11-15 — delta mutation: `on_conn_closed`

a delta mutation run over the connection summary, 31 schemata mutants,
ReleaseSafe, one build, each mutant under `setsid -w timeout` and `ulimit -v`: the accept-failure refusal (hook
skipped, requests, duration, end), `connMain`'s summary defer (start stamp, default end, requests, peer, the
duration's subtraction and value, end, hook presence), each of the four assignments of `end`/`requests` (h2c preface
failure, h2 exit, h1 exit), every arm of `connEnd` (read and write `timed_out`, read and write `errored`, the
`canceled` exclusions, the `normal` result), and the request counter in `serveLoop` and `h2_server`'s `serveJob`
(skipped, counted twice). 29 killed in the first run; 2 survived: a read or write that ended in cancelation was not
tested to be `normal` rather than `errored` (the `!canceled` guards). The first attempt to reach them (cancel `serve`
while blocked in accept) was consumed by the accept; cancelling after `shutdown` reaches the connection tasks, and the
new test killed both. The first-run tests were also tightened (duration bounded by the test's own span and by the
deadline, the h2c pre-preface timeout and reset, a write stall against a reset during the write, the slab-size
refusal in `connMain`). 31/31, 0 equivalent. Not mutated: the defer ordering (summary after `.closed`), structural
rather than a value.

## 2026-11-13 — delta mutation: client interceptors

a delta mutation run over every function commit `1a338774` touched — the dispatch at the top of `request`/`requestPlain`, `requestIntercepted`, `Chain.proceed`, `checkDeadline`, `totalDeadline` (schemata, ReleaseSafe, strict verdict): 29 mutants, 28 killed (6 by the hang cap), 1 equivalent (`checkDeadline`'s `<= 0` → `< 0`, different only at a remainder of exactly 0 ns — needs an injectable clock). Seven tests were added first, because the existing ones let mutants through: with a budget set, `runBounded` cancels a retrying chain before `Chain.proceed`'s own deadline check is ever needed, so that check is now pinned under `inline_blocking`, where it is the only bound; also method/url/options reaching the exchange incl. an interceptor rewriting them, an outer retry re-running inner interceptors, no budget keeping the chain on the caller's thread, `request` on the TLS-capable and `requestPlain` on the http-only exchange, invalid options refused before any interceptor runs, an interceptor's error crossing the bounded path. No defect. The 2026-11-13 HPACK delta and the 2026-11-12 halves below still cover the rest.

## 2026-11-13 — finding fixed: decoded HPACK values freed unwiped

Fixed 2026-11-13: decoded HPACK storage, `HeaderList.deinit` and dynamic-table entries are zeroed before every free; `zeroize` gained `ensureUnusedCapacityWiped`/`toOwnedSliceWiped`; ReleaseFast freed-block tests in `hpack.zig`. The finding as recorded by the 2026-11-12 delta run:

**FINDING (LOW-MED, defence in depth, 2026-11-12 delta run): decoded HPACK values are freed unwiped.** `zeroize.zig` states that header blocks and credentials must not survive a `free` in ReleaseFast, and the raw h2 header-block buffers are wiped — but `hpack.Decoder.decodeBlock`'s `storage` (every decoded name and value, `Authorization` and cookies included) grows by plain `appendSlice`, is shrunk by `toOwnedSlice` (a failed remap moves it and frees the old block as is), and `HeaderList.deinit` frees it without a wipe; dynamic-table entries evicted or freed at `deinit` are not wiped either. Fix: wiped growth and shrink for `storage`, `zeroize` in `HeaderList.deinit` and on dynamic-table eviction/`deinit`, with the freed-block test of `h2.zig` extended to decoded values; then a delta mutation run.

## 2026-11-13 — the 52 open test-gap candidates of the 2026-11-12 partial client run, decided

Decided: 19 killed, 33 equivalent, 0 findings. Killed by new or already-present tests (16, proven by a schemata run: each mutant fails the new test): the stale-pooled-connection retry with TWO stale idle connections must dial fresh (`request` and `requestPlain`), `trailersTruncated` (head filling `max_head_bytes`, no trailer, dropped trailer line, non-chunked body, h2), `Member` flush and `drain` byte count, `initCompress` resetting a dirty `history_end_unhashed`, `PaddedSource` room checks, `conditional` list elements (a malformed element before a tag, the empty tag `""`), `redirectLocation` trailing slash and an empty path part, and the existing one-digit-port test for `client_proxy`; three more (`gzip.initCompress`'s comptime field check) are killed at compile time, since the mutant does not build. Equivalent, each with its invariant: `= undefined` poison writes (3), initial values always overwritten before a read (`reused` x2, `Gunzip` crc/size x4), `owned = false` before a `continue` with no fallible step (x2), a retry `h1_only` read only behind `take_idle` (x1), an unreachable `trailer_bytes_seen == 3`, a `Member.writer = .failing` that std's `Compress.finish` already implies, `decode_out_len`/`decode_in_len` +-1 (buffer granularity only, x4), `setEvalBranchQuota` headroom and the field-check's `@compileError` body (comptime, a std change is the needed injection), `conditional` callers' range guarantees (x3), and in `cleanPath` the skipped-slash and `..` bookkeeping variants (x9) plus `resolvePath`'s one-byte-path `trailing`. Table kept by the auditor; the next whole run needs none of these.

## 2026-11-12 — whole-file run of the server half, delta run of the client half

the SERVER half (Server, h2_server, h1, body, form, multipart, servecontent, sse, problem, crossorigin, hostguard, bufpool, zeroize) had a new whole-file run — 3827 mutants, ReleaseSafe schemata plus a ReleaseFast build for the `zeroize` sites, strict verdict: 3667 killed, 101 equivalent, 59 unobservable (bind/listen/accept errno mapping, the reader's expired-flag re-tests, clearing `control.tr`/`tw` after the loop — each needs fault or race injection), 0 undecided, no defect; four former line-range "equivalents" in `h1.zig` were not and are now killed. The CLIENT half changed by ~15 production lines since the clean 2026-11-07 run (h2 raw-buffer wipes, the proxy credential wipe, `url.hexVal`), so it had a DELTA run over the touched functions: 45 mutants, 44 killed (wipes in ReleaseFast with a test that counts freed blocks still holding header bytes; the h2 guards on an h2-only binary with a clean subset baseline), 1 equivalent (`beginAssembly` appends to an empty list: no old block to free), 0 undecided. A partial extra run over the client files (1635 of 5200 mutants) left 52 open test-gap candidates — Backlog. 2026-11-13: the HPACK decoded-value wipe (decoder storage growth and shrink, `HeaderList.deinit`, dynamic-table eviction and deinit, the two new `zeroize` helpers) had a DELTA run, 31 mutants in a ReleaseFast schemata build: 25 killed, 6 equivalent (cost-only growth boundaries, the `len == capacity` fast path, a double wipe of an empty result, a zero-length `alloc`), 0 undecided; one survivor of the first pass was a real test gap (an in-place shrink to zero freed the block unwiped) and is now killed. The 52 test-gap candidates of the partial client run are decided (Backlog). Comments citing a private audit path were reworded.

## 2026-11-07 — whole-module mutation run

A WHOLE-MODULE run in four waves, mutant schemata over every production file in ReleaseSafe, burns judged in ReleaseFast on uninstrumented or single-mutant builds. 3148 mutants: 2927 killed, 221 equivalent (invariant per id in the tables: perf-only thresholds, defensive duplicates, ns-granularity and single-listener paths, hpack collision-only paths, `min`/re-check fast paths, unreachable-by-construction states), NOT counted and NOT mutated: 36 hpack comptime-table conditions (not mutable at runtime) and 36 former contract-panic guards. Wave 1 excluded those guards because a panic cannot be observed in-process; during the run they became error returns (no `@panic` is left in production code), and each one is pinned by a direct `expectError` test rather than a mutant. Defects the run found and fixed: unbounded streaming h2 body growth, `Detached.push` on a closed stream, a second GOAWAY raising last-stream-id, client trailers without END_STREAM, `delHeader("Trailer")` leaving set values, request bytes freed unzeroed on buffer growth/free (`zeroize.appendSliceWiped`), the base64 proxy credentials left on the stack. The earlier delta (2026-11-01, 60 mutants over `HostGuard`, bind mapping, timeouts) is subsumed.

## 2026-10-05 — Go standard library differential oracle: defects found

When the oracle was first run (h1, serve, url and multipart areas, then the client area the same day):

It found six defects here, all fixed the same day with
tests that fail without the fix (13 schemata mutants over the fixes, 13 killed):
`Transfer-Encoding` split over two field lines was judged line by line, so `gzip` + `chunked`
framed as chunked while the same list on one line was refused (TE.TE desync); an HTTP/1.0 request
with `Transfer-Encoding` was decoded as chunked instead of refused (RFC 9112 §6.1 MUST); a comma
inside an entity-tag split the tag (`If-Match: "x,"v1"` matched `"v1"`); `*` asked for an ETag
rather than for a representation, so a resource with only `Last-Modified` let `If-None-Match: *`
through; `31 Feb` parsed as 2 March; a malformed or folded part header in multipart was skipped,
so a folded `Content-Disposition` lost its `name`. The client area (added the same day) found two
more: a response `Transfer-Encoding` other than the sole `chunked` was framed as chunked anyway (or
read to close) and handed over still coded, HTTP/1.0 + TE was decoded; and obs-fold in a response
was refused where RFC 9112 §5.2 makes a user agent unfold it (6 mutants, 6 killed).

## 2026-10-04 — h2spec: first run

The first run failed 3.8/1 and 7/1: after the client's GOAWAY the
session returned without a GOAWAY of its own, and the socket was closed with the client's next
PING unread, so the kernel reset the connection. Fixed (GOAWAY(NO_ERROR) once the peer's streams
are served; `Server` closes h2c connections lingering: write side shut, ≤ 64 KiB read and dropped,
then close), each with a regression test that fails without its half (mutation-checked; the
lingering one deterministic: a GOAWAY followed by 32 KiB of PINGs, `ConnectionResetByPeer` 3 of 3
without it). The suite needs no fixture: it is the oracle, run before a release.

## 2026-07-30 — trailers and h2 streaming: mutation checks against curl

Self-interop cannot catch a shared misreading of the framing (the writer and reader agree on the same mistake); mutation testing confirmed the difference: emitting the h1 trailer block before the last-chunk line fails curl outright (exit 56), and leaving END_STREAM on the last h2 DATA frame makes curl/nghttp2 *silently discard* the trailer frame and still exit 0, so on h2 the load-bearing assertion is the surfacing check rather than the exit code. For h2 server streaming, 9 mutations were run and each turned tests red; the sharpest is arrival-driven crediting on the streaming surface (8 tests red, 2 of them curl's).

## 2026-08-14 — anchoring work

The anchoring work landed. DONE 9dee82e: h11 on framing; fixed a misquoted RFC 9112 2.2 in comments
