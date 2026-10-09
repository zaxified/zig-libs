# accesslog — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
