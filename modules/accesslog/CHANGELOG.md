# accesslog — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-12** — **NO CONSUMER-VISIBLE CHANGE:** Second whole-module mutation run (operator-generated schemata over the production code of `root.zig`, `logformat.zig`, `middleware.zig`, `sink.zig`, `timefmt.zig`, `filewriter.zig`; tests only): six new tests pin what the run left alive: `end:` formats with no latency add nothing (not even one nanosecond before a second boundary), one-letter strftime tokens (`%u`, `%p`) directly after another token, the `%C` century divisor (1999 and 2100), `RotatingFile` holding one descriptor with `max_backups = 0` and two with a positive one, a record over `max_size` rotating a file that holds a single byte on both write paths, a `Sink` line of exactly `direct_line_max` bytes written whole (one write, not streamed), and `RotatingFile` slices before a huge splat saturating the byte count.

- **2026-11-08** — **NO CONSUMER-VISIBLE CHANGE:** the JSON string escaper and its UTF-8 classifier (`writeJsonString`, `utf8Step`) moved to the new `jsontext` module; `writeJsonString` is now a call to `jsontext.writeString(w, s, .{})` and the output bytes are identical. The two `utf8Step` tests moved with it; ReleaseFast bench (`ACCESSLOG_BENCH=1`) ASCII row 271.4 → 273.9 ns. New dependency: `jsontext`.

- **2026-11-07** — **NO CONSUMER-VISIBLE CHANGE:** Whole-module mutation run (1026 schemata mutants over `root.zig`, `logformat.zig`, `middleware.zig`, `sink.zig`, `timefmt.zig`, `filewriter.zig`; tests only): 983 killed, 43 decided equivalent or unobservable, 0 undecided. 23 new tests pin what the first pass left alive: raw non-ASCII bytes in a quoted logfmt value, `%h` quote/backslash and `[%t]` bracket handling, `hostOnly` with two `]`, the method taken from the request, `%l` versus `%u`, control-byte bounds and UTF-8 in a `%{format}t`, the saturated latency at the top of i64, the offset-shifted wall clock, every pair of adjacent strftime directives, a hand-built `timefmt.Spec` (bad or oversized format is `-`, a dead writer is `WriteFailed`), `RotatingFile` (name bounds, handle release on close, no rotation on a closed file, rotation arithmetic at the top of u64, a pending reopen that adopts a foreign file, permissions of the rotated file, `isBackup` shape, a failed prune recorded, `max_backups = 0` set after open, the clock at the top of i64, a refused rename), `Sink` (a line over the direct limit, unsynchronized leaves the batch alone, no flush of an empty batch), `Logger` (the eighth captured response header, a handler error under the body cap is 500 not 413).
- **2026-11-06** — **Fix (delta audit H):**
  - `RotatingFile`: the Writer after `close()` panicked when the write would have rotated; it is now `WriteFailed`.
  - Pruning reads its own `.iterate` handle of the directory. A caller's O_PATH `Dir` used to make the read an `errnoBug` panic in Debug.
  - A live file deleted or moved under the writer now starts a new file. Before, rotation kept failing and records went to an unlinked inode.
  - The new file after rotation is opened without truncating, so a file another process created under that name is appended to.
  - Pruning also counts entries of `.unknown` kind.
  - `drain` length arithmetic saturates.
  - `Sink`: on the direct paths (`synchronized = false`, or a line longer than the batch) a line is rendered whole and written in ONE call, up to `Sink.direct_line_max` (8 KiB). Before, it went out piece by piece and a rotation could split it across two files.
  - README/SPEC no longer say `%{Name}o` is rejected.
- **2026-11-06** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit H of the M-row code (tests only): `Sink` template on every path, `Logger.response_headers` cap and `utc_offset_min`, `%{format}t` 12-hour/weekday/offset-clamp edges, `RotatingFile` name limits, hostile-clock backup names, `_NN` pruning order and look-alikes, a Writer call as one unit, and a rename-ok/create-fails (EMFILE) rotation that recovers.
- **2026-11-06** — **Added:** `RotatingFile` (`filewriter.zig`), a size-rotated log file as a `std.Io.Writer` (phuslu/log `FileWriter`): rotation on write at `max_size`, timestamped never-overwritten backups, `max_backups` pruning, `file_permissions`, `utc_offset_min`; a failed rotation never loses a record (written to the current file, counted, retried). Grade probe core gap.
- **2026-11-06** — **Added:** `LogFormat` `%{Name}o` (response header from the new `Entry.response_headers`, escaped; `Logger.response_headers` fills it from the router's response), `error.BadHeaderName`, and `Sink.Options.template` so a `LogFormat` drives a `Sink`/`Logger`. Grade probe core gap.
- **2026-11-06** — **Added:** `LogFormat` `%{format}t` (Apache `mod_log_config`): strftime formats rendered through `datefmt`, `begin:`/`end:` prefixes, `sec`, `msec`, `usec`, `msec_frac`, `usec_frac`; `Entry.utc_offset_min` / `Logger.utc_offset_min` for the wall clock and `%z`; `error.BadTimeFormat`. New dependency: `datefmt`. Grade probe core gap.
- **2026-11-05** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit of `%{ms}T`/`%{us}T`/`%{s}T` (`c65d2d91`): 12 mutants, 12 killed. unit spelling (case, padding, wrong conversion letter, unterminated), truncation edges and `maxInt(u64)` pinned against `%D`/`%T`.
- **2026-11-05** — **Added:** `LogFormat` reads Apache 2.4.13's `%{ms}T`, `%{us}T` and `%{s}T` (latency in that unit, truncated; `-` when not timed); any other unit is `UnknownDirective`. Grade probe core gap.
- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit of the no-panic sweep: 1 mutant (the latency fix reverted), killed. Cumulative 374/381, 7 eq. Card A1 again.
- **2026-10-29** — **Fix (no-panic sweep):** `Logger` computes `latency_ns` without overflow when an injected clock spans the whole i64 range (was an overflow trap, UB in ReleaseFast). Request fields, log formats, writers and the sink were clean.
- **2026-10-25** — **Fix (A1 review):** Combined (and `LogFormat`) no longer hex-escape `]` in quoted fields: `/q?a[]=1` is logged as sent, as Apache logs it (it came out as `/q?a[\x5d=1`); `]` stays escaped inside `[%t]`. `%h` escapes space, `"`, `[` and `]` like `%u` and is `-` when empty (a hand-built `remote_addr` with a space shifted every later field; an empty one left the slot blank). An HTTP/2 request is logged as `HTTP/2.0` (was `HTTP/1.1`). `Logger` on a handler error: a chunked body over `max_body_bytes` is logged as the 413 the server answers (was 500) with `%b` `-`; after the head went out, the status and bytes that were sent. New `writeClfHost`/`writeClfTime`. Mutation tests (sweeps, `LogFormat`, middleware, sink capture) and the U+FFFD lead test. **Card:** grade 1 — fastest JSON writer measured (0.89× phuslu/log), scope ahead, fresh audit.

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** tools ported to Zig 0.17.0 (compile only): `tools/interop.zig`: `dupeZ` -> `dupeSentinel`, `Ast.parse` takes `.{ .mode = .zig }`.
- **2026-10-12** — `fromRequest` logs the method as sent (`Request.methodName()`): an extension
  method (http R9) appears by its name, not as an empty string.

- **2026-10-11** — Added (scope core → parity; survey 2026-09-30 backlog): `Entry.extra: []const Field` (caller key/value pairs in JSON Lines and logfmt, same escaping; a key outside `[A-Za-z0-9_.-]{1,64}`, a fixed key or a repeat is skipped, so no field can be forged or shadowed; empty = byte-identical output); `LogFormat` (`parse` / `comptimeParse` / `write`: Apache 2.4 `LogFormat` templates `%h %l %u %t %r %s %>s %b %B %D %T %m %U %q %H %%`, `%{Referer}i`, `%{User-Agent}i`, `%{key}x`; every value through the Combined escaper; the Combined template renders byte-identical to `writeCombined`); `Logger`, a `router.Middleware` writing one line per request to a `Sink` with an injected clock, optional id/user/extra functions and `keep` for conditional logging / sampling. `FromRequestOptions` gains `user`, `extra`. New dependency: `router`.

- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-accesslog`, kept instrument kind 3): card Performance 0.13–0.33× Go encoding/json + log/slog + go-logfmt (JSON Lines and logfmt; Combined has no timeable reference), measured on a quiet host. Tooling only, no code change.

- **2026-10-09** — tests: deterministic fuzz driver `ACCESSLOG_FUZZ` over the existing harnesses.

- **2026-10-06** — ADDED: `Sink` — the thread-safe access-log writer over one shared `std.Io.Writer`
  (`init(writer, .{ .format, .synchronized, .io })`, `log(entry)`): a group commit, never a lock held
  across the write, never a torn or interleaved line. Moved from `metrics.AccessLog` (removed there)
  with its concurrency tests and opt-in F4 bench (`ACCESSLOG_BENCH_F4=1`); it now writes this module's
  full formats. `meta.concurrency` reentrant → threadsafe. Also moved: the JSON-path oracle
  (`tools/json_path_oracle.py`, `src/json_path_vectors.zig` — 333 paths read back as Python's
  `decode('utf-8', 'replace')`), replayed here through `writeJsonLines`' `target`; all pass.

- **2026-10-05** — **Anchoring: JSON Lines read by Python json, Go encoding/json and jq; logfmt read by go-logfmt**
  (`tools/json_oracle.py`, `tools/go_json`, `tools/go_logfmt`, `tools/interop.zig`, `src/json_oracle_test.zig`): 421
  entries with hostile and ill-formed strings and extreme numbers; each reader gets every entry back exactly, the
  U+FFFD substitution matching Python's own decoder. Anchor grade MIXED → EXTERNAL.
  - **DEFECT fixed, BEHAVIOURAL:** logfmt wrote a control byte as `\xHH`, which go-logfmt (the de-facto reference
    reader, and Loki's parser after it) refuses as an invalid quoted value -- one control byte in any field made the
    whole line unreadable. Now `\u00HH`, the JSON-style escape those readers decode. Combined keeps Apache's `\xHH`.

- **2026-10-04** — **Tests:** mutation run (33 schemata mutants, all killed after one new test:
  a logfmt value holding DEL is quoted and hex-escaped). No code change.

- **2026-09-28** — `response_bytes` is now known for streamed responses (chunked, compressed,
  HTTP/1.0 until-close), from `http`'s `ResponseWriter.bodyBytesSent`; they logged `-` before.
  Wanted by qap M11.5c.

- **2026-09-25** — **New `Entry.user`: the authenticated caller.** Combined writes it as `%u`
  (was always `-`); JSON Lines and logfmt gain a `user` key. `%u` is unquoted, so a space, `"`,
  `[` or `]` in it is hex-escaped (`\xHH`) on top of the usual escaping, and an empty user is
  `""`. Null -- the default -- writes exactly the old output in all three formats (JSON Lines
  omits the key rather than writing `null`, so no existing line changes).

- **2026-09-10** — A1 audit close-out, 3 findings. (1) Combined's
  `writeClfEscaped` now hex-escapes `]` the same way it already hex-escapes
  control bytes: `]` is the one non-control byte that is also a delimiter
  here (`time_formatted` sits inside the unquoted `[%t]` bracket), so a
  hand-built `Entry` could otherwise splice fabricated content past the real
  bracket close. `entryFromRequest` can never produce this (`time_formatted`
  comes from trusted formatting code, never a header) but SPEC's threat
  model explicitly covers "any string field" of a hand-built `Entry`.
  Measured: RED (a crafted `time_formatted` put 2 raw `]` bytes on the wire)
  → GREEN (1). (2) The SPEC/code key-count mismatch (SPEC.md's field table
  and JSON key list were already fixed by `91d2744d`, 2026-09-01) is now
  closed in README.md's quick-start example too, which still rendered the
  pre-`trace_id`/`span_id` 12-key JSON comment. (3) The three fuzz harnesses
  and the anti-degeneracy corpus test not reaching `trace_id`/`span_id` were
  already fixed by `91d2744d` — verified structurally against `91d2744d^`
  (7-slot `ill_formed` → 9-slot) and confirmed green in the current suite;
  no further code change needed.
- **2026-09-08** — Test-only, no production change: `fuzzEntry`'s five numeric draws
  (`timestamp_ns`, `status`, `request_bytes`, `response_bytes`, `latency_ns`) were dead on
  every corpus replay. They come after the field payloads, each corpus entry stopped at the
  last payload, and a `Smith` value draw with fewer than eight octets left returns its
  weight minimum — so measured across the seven seeds: **0 carried a nonzero status, 0 a
  negative timestamp, 0 a nonzero latency**, and the widest JSON record the whole corpus
  could render was 937 octets. The three fuzz targets `fuzzJsonLines`, `fuzzLogfmt` and
  `fuzzCombined` all read that same corpus, so all three rendered `status: 0` and
  `"latency_ns": 0` for ever. `fuzzCaseNumeric` now appends the five eight-octet words to
  four of the seven seeds (the other three keep the all-minimum record on purpose, since it
  is a real shape); the new `corpus:` guard pins the measurement at **4 nonzero statuses, 2
  negative timestamps, 4 nonzero latencies and a widest record of 1015 octets** — the last
  being the standing check that the harness's 4096-octet buffer absorbs the worst case.
  ⚠ `status` is a `u16`: its word is read as a little-endian u64 and a value above 65535
  falls outside the type's weight range and comes back as 0, not truncated.

- **2026-08-06** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. ⚠ **This entry used to begin "Verified
  against a live capture from Apache `mod_log_config` (Combined Log Format +
  `ap_escape_logitem`) + Heroku/`kr/logfmt`". There is no such capture** — corrected
  2026-09-03. Apache and logfmt are the *format* this module writes, which is what
  `root.zig`'s `meta.model_after` says; the sentence was a template rendering a
  C-reference-implementation field as a claim of a verified capture, and the same
  template put the same false sentence in four other modules. The half after the
  semicolon was true and stays: `goaccess` 1.10.2 is a genuine live external anchor,
  and it is anchoring in the direction that suits a FORMATTER — a foreign parser
  reading our output, not a capture of foreign output. It earned its place, finding a
  real defect (`%h` carried `host:port`, which goaccess rejected on 100% of lines,
  while three in-house tests asserted the same wrong shape). ⚠ It anchors **Combined
  only**: JSON Lines and logfmt have no foreign parser and are self-tested, as
  SPEC.md §Anchoring states.
- **2026-07-22** — New module: structured HTTP access-log formatter — JSON Lines /
  logfmt / Apache Combined with rigorous log-injection escaping (untrusted
  UA/path/referer can't forge a line or inject fields).
