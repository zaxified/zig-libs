# accesslog — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
