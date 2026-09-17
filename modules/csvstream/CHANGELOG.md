# csvstream — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-17** — ⚠ **Memory leak on the error path, attacker-reachable.** The
  F7 cleanup (2026-09-02) recorded which `buf` slots held unescaped copies in a
  fixed `[64]usize`, under an `if (owned_n < owned.len)` guard. The 65th copy
  onwards was allocated and never recorded, so the `errdefer` freed 64 of them
  and stranded the rest — unreachable, since the caller never receives the
  slice on an error return.
  - The reachable shape needs no allocation failure: a record with more fields
    than the field buffer holds fills the buffer with copies and is then
    refused. The field count comes from the input file. Measured on 15,000
    fields of 10 KB each, each containing a doubled quote, split into a
    4,096-slot buffer: **4,096 copies made, 64 freed, 40,324,032 bytes stranded
    on a single call**, on the default (refusing) policy.
  - Fixed by asking the ADDRESS instead of keeping a list: a field that was not
    unescaped is a sub-slice of the record by construction, an unescaped copy
    is a separate allocation and cannot be. No ceiling to exceed, and nothing
    allocated in a path that runs when an allocation has just failed.
  - The existing regression test pinned this invariant at TWO escaped fields,
    which is why it kept passing. The new ones use 200 and 400, and all three
    go red against the old code (measured: 3 of 3 fail, 83 leaks). One of them
    is the other direction — mixing borrowed and copied fields, so a cleanup
    that freed the whole buffer indiscriminately hands `testing.allocator` a
    pointer it never issued.
  - Note for callers on the SUCCESS path: `StreamReader`/`ChunkReader` bound a
    single record at `max_record_len` (10 MiB by default), so the front door
    refuses this shape with `error.RecordTooLong` before `splitFields` sees it.
    The leak was reachable through the in-memory API, where the caller already
    holds the bytes.

- **2026-09-17** — `splitFields`'s field-buffer overflow behaviour is now the
  caller's choice. Additive: `splitFields`/`nextFields` keep today's signatures
  and today's behaviour, and the F2 refusal stays what an uninformed caller
  gets.
  - New `splitFieldsOpts` and `StreamReader.nextFieldsOpts` take
    `SplitOptions{ .on_overflow }`, where `OverflowPolicy` is `.@"error"`
    (default, unchanged) or `.truncate` (fill the buffer, drop the surplus).
    Passed as a literal the branch folds away.
  - Per CALL, not per reader and not a build option: a converter generally
    wants to hear about an over-wide HEADER and not about over-wide rows, and
    those are two call sites in one binary. No module under `modules/*/src/`
    consumes build options; `StreamReader.Options` is the precedent for caller
    policy, and `init`/`initMax` for an additive variant.
  - ⚠ A `.truncate` caller takes on F3, the composed failure: a header and its
    rows split with the same buffer truncate to the same width, so
    `validateArity` reports a match and `Header.len()` returns a count the file
    does not have. `countFields` gives the true width and is how the case is
    detected. Documented on the enum member itself.
  - The `errdefer` that frees alloc-owned (escaped-quote) fields runs only on
    an error return, so `.truncate` returns them intact — which is also why
    "ignore `FieldBufferTooSmall` and read the buffer anyway" was never a
    workaround: those slots come back freed and the caller cannot tell which.
    Pinned by a test that frees the owned slot itself, so `testing.allocator`
    fails on a double free as well as on a leak.
  - Requested by a downstream consumer whose contract is template-strict,
    data-lenient: a malformed template is a hard failure, malformed input data
    must still convert.

- **2026-09-09** — Docs: the `NOTICE` pointer in ``src/csv_spectrum_vectors.zig`` resolved to `modules/NOTICE`,
  a path that has never existed in this repository. Now ``../NOTICE``. No code or data
  changed. `zig build check-catalog` gained a check that resolves every relative NOTICE
  link under `modules/**`, so this cannot come back silently.
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
