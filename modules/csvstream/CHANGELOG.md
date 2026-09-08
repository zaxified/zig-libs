# csvstream — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Licensing correction, no code change. `NOTICE` concluded that because
  csv-spectrum commits no `LICENSE` file "there is no license TEXT to reproduce". That
  inference was wrong: `BSD-2-Clause` in `package.json` is an SPDX identifier naming a
  published text, and its clause 1 binds a redistributor whether or not upstream
  committed a copy. The text is now reproduced. Also re-measured: the upstream repository
  has MOVED — `maxogden/csv-spectrum` redirects to `max-mapper/csv-spectrum` — and the
  URL in `NOTICE` now says so. Pinned commit and vendored bytes unaffected.
- **2026-09-07** — **Both fuzz harnesses were replaying an EMPTY record with
  quoting DISABLED, and now sweep the knobs over a seeded corpus.** Each opened
  with `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u16, 0, buf.len)`;
  `bytes` consumes `min(buf.len, in.len)` octets and the ranged draw then reads
  eight *more* as a little-endian u64, returning the range minimum when fewer
  remain — so the drawn length was 0 for every input a seed can carry.
  `fuzzLineIterator`'s `steps <= len + 1` bound had therefore never executed once:
  with `len == 0` the first `next()` returns null. Worse, `quote` (and, in
  `fuzzSplitFields`, `delimiter`) were drawn AFTER the bytes and so were always 0
  — `quote == 0` means "no quoting at all", so the entire quoted-field scan, the
  `LazyQuotes` rule of the 2026-09-02 F1 fix, the doubled-quote unescape and its
  allocation path, and `unbalanced_quote` were unreachable from any input the
  harness could ever be handed. Now one `smith.slice(&buf)` draw plus an explicit
  sweep over `quote ∈ {'"', 0}` and `delimiter ∈ {',', ';', '\t'}`, with a
  10-seed record corpus and an 11-seed field corpus. Measured 2026-09-07:
  0 records, 0 fields and 0 `unbalanced_quote` flags before; 17 records,
  3 unbalanced flags (0 with quoting off), 86 fields and 2 `FieldBufferTooSmall`
  refusals after.
- **2026-09-02** — Drift re-audit (W2, window `0575340..HEAD`). Nine findings, all fixed.
  Oracles: Python 3 `csv` and Go `encoding/csv` with `LazyQuotes=true` (the model this module's
  own docs name), over ~21 700 random reader inputs and ~6 000 writer rows.

  - **HIGH, silent column shift:** `splitFields` ended a quoted field at the closing quote even
    when the next byte was not the delimiter — so **a field boundary was emitted at a position
    where the input contains no delimiter**. `"a"b` became two fields, `"a,b"c,d` three;
    `unbalanced_quote` stayed `false` because the quotes really were balanced. File content
    therefore chose a row's column count. Now Go's rule: a lone quote followed by anything other
    than a delimiter or end-of-record is a literal quote, and a field ends only at a delimiter or
    at end-of-record.
  - **HIGH, silent data loss:** a record with more fields than `buf` holds had its surplus dropped
    without a word, though the signature has an error channel. Now `error.FieldBufferTooSmall`,
    plus a public `countFields` so the "buf must be large enough" precondition is one a caller can
    actually evaluate.
  - **HIGH, the two composed:** header and rows split with the same buffer were truncated to the
    same width, so `validateArity` **reported a match** and `Header.len()` returned the truncated
    count as the true one. With `user,note,role` and the row `"alice"x,ok,admin`, every guard the
    module offers passed and `role` read `ok`.
  - **MEDIUM:** `writeRecord(&.{""})` emitted a bare terminator, which the reader skips as a blank
    line — a legitimate one-column row vanished on read-back. It is now quoted, as `csv.writer`
    does. This was the **only** divergence from Python's writer across 6 000 random rows, and the
    module's own test asserted it as correct.
  - **MEDIUM:** `max_record_len` had a hard 10 MiB floor the caller could not lower and no knob in
    `StreamReader.Options` at all, against a README/SPEC promise that "peak is the chunk size, not
    the file size". Asking for 1 KiB chunks permitted a 1 MiB allocation with no error. It is an
    option now and defaults to the chunk size. The prior ledger's "bounded-memory guarantee
    restored" PASS was restored against *unbounded* growth, not against the guarantee as written.
  - **MEDIUM:** EOF was decided from the `stat.size` taken at `init`, never from a short read. Two
    silent failures: any readable file whose `stat.size` is 0 — every `/proc` file — yielded zero
    records, indistinguishable from an empty one; and bytes appended after `init` were dropped
    with the last partial record emitted as if complete. EOF now comes from a read returning 0.
  - **LOW:** `splitFields` and `unescapeQuotes` both leaked on a mid-record allocation failure —
    the caller never receives the slice, so the earlier fields were simply unreachable.
  - **LOW:** `Header.init` is public and `@intCast`ed an arbitrary `fields.len` to `u32`, after
    which `putAssumeCapacity` would overrun the map. Now `error.TooManyColumns`.
  - The shipped example split into `[8][]const u8` buffers, so any 9-column CSV lost columns there.

- **2026-08-18** — Portability fix (`check-portable`): a test indexed the in-memory
  `body` fixture with `rec.byte_offset` directly; `byte_offset` is `u64` deliberately (a
  real file offset can exceed a 32-bit `usize`), which fails to compile as a slice index
  on a 32-bit target. Added the same narrowing `@intCast` already used one test above for
  `chunk_start_in_file` — `body` here is a 25-byte in-memory literal, so the live value is
  always tiny and the cast is safe without changing `byte_offset`'s production type.
  Compile-only; no behavioural test added. Verified: `zig build portable-csvstream` and
  `zig build test-csvstream --summary all` (73/73) both green.
- **2026-08-14** — `zig build check-fuzz` coverage restored: `src/line.zig` already had
  two `testing.fuzz` harnesses on the real decode entry points (`LineIterator.next`,
  `splitFields`) — genuinely running, catching nothing — but they were spelled `t.fuzz(`
  through this file's `const t = std.testing;` alias, and the gate greps source text for
  the literal substring `testing.fuzz(`, so they were structurally invisible to it. Both
  now call `std.testing.fuzz(` spelled out. No behavior change; no new coverage — the
  module was already fuzzed, the gate just couldn't see it.
- **2026-07-19** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Go
  `encoding/csv` (LazyQuotes), Python `csv`, `libcsv` (design reference, not a test
  anchor).
- **2026-07-09** — New module: Streaming RFC 4180 CSV reader that preserves byte
  offsets, bounded memory regardless of file size.
