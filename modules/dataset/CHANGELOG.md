# dataset — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **A1 fix campaign: four findings from the third audit.**
  - `Value.order` reached `std.math.order`'s `unreachable` on NaN — reachable
    directly from `deserialize`, which hands a `.float` cell any bit pattern
    from 8 wire bytes with no finiteness check. Debug/ReleaseSafe panicked,
    ReleaseFast silently returned `.gt`. Now defined and total in every mode:
    NaN sorts as the greatest value, NaN == NaN. Regression: 20/22 pass, 1
    fail, 1 crash (`unreachable`) before the fix; 22/22 after, Debug and
    ReleaseFast.
  - `toJson`'s `appendJsonString` copied `.text` bytes verbatim, so an invalid
    UTF-8 cell (reachable the same way — `deserialize` bounds `.text` LENGTH,
    not content) produced a JSON document that was not valid UTF-8 at all, not
    just an invalid cell. Now validates each multi-byte sequence and
    substitutes U+FFFD one byte at a time on anything that doesn't decode.
    Regression: `utf8ValidateSlice` on the output false before, true after,
    for the same `"\x80\xff"` input; a positive control (valid multi-byte and
    4-byte sequences) still passes through byte-identical.
  - `deserialize` had no doc comment stating that a failed decode does not
    unwind its partial allocations (the contract lived only inside a test's
    comment) — now stated on the function itself, alongside the exact
    amplification factor between wire size and the memory an accepted
    document occupies (measured 48.0–48.1×, flat from 64 KB to 8 MB input,
    worst case `ncol = 1`). `toJson`'s unbounded output-size factor (one
    9-byte wire float -> 379 bytes of JSON, `5e-324`) is now documented the
    same way.
  - The `fuzzDeserialize` harness that used to replay one empty image forever
    (2026-09-07 entry below) and the two `@intFromFloat` guards (2026-09-03
    entry below) were re-verified as still correct in this pass, not touched.
- **2026-09-07** — **`fuzzDeserialize` was replaying an EMPTY image, and now has
  a 13-entry corpus with a measured reach guard.** It opened with
  `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u16, 0, buf.len)`;
  `bytes` consumes `min(buf.len, in.len)` octets and the ranged draw then reads
  eight *more* as a little-endian u64, returning the range minimum when fewer
  remain — so the drawn length was 0 for every input a seed can carry and
  `deserialize` failed on its very first `u32v()`. With no corpus either, the
  target ran that one empty input for ever, which means the `ncol`/`nrow` count
  bounds (both found by an actual fuzz sweep, one of them a 32 GB `total-vm` OOM
  kill) had no regression coverage from it at all. Now one `smith.slice(&buf)`
  draw, a corpus of ten malformed wire images (both count bounds, a bad type tag,
  an unknown value tag, two 4 GB length claims) plus three built by `serialize`
  itself at run time — the empty image, one carrying every column type and every
  value tag including the appended `decimal` tag 5, and that image truncated by a
  byte. The harness also now walks the decoded rows instead of discarding the
  result. Guard pins cells decoded rather than "accepted > 0", because the empty
  image is accepted and carries no cells: measured 0 accepted / 0 cells before,
  2 accepted / 12 cells after.
- **2026-09-03** — Two unguarded `@intFromFloat` conversions on public API, found
  while auditing `jsonshape` (its `.int`/`.decimal` columns route here). New
  `Value.floatToInt`, and both sites go through it.
  - `Value.asInt` did `.float => @intFromFloat(f)` with no range check. Out of
    range is undefined behaviour: it panics in Debug and ReleaseSafe and yields
    silent garbage in ReleaseFast, so it was not a conversion untrusted numbers
    could be handed to. Now returns `null`, which the doc already implied for
    the `decimal` arm.
  - `Value.cast(.decimal)` guarded the **wrong value**: `isFinite(f)` while the
    conversion was of `f * decimal_scale`, a different number by twelve orders
    of magnitude. `1e30` is finite; `1e42` does not fit `i128`. The bound is now
    checked on the scaled product that is actually converted.

- **2026-08-18** — Portability fix (`check-portable`): the `"serialize rejects a length
  that overflows the u32 wire field"` test crafted an oversized slice via
  `(@as(usize, 1) << 33)` to probe the `error.TooLarge` guard. On a 32-bit target
  `usize` and `u32` share the same range, so no `usize` length can ever exceed
  `u32::max` there — the scenario is unreachable, and the `<< 33` literal doesn't fit
  `Log2Int(usize)` (`u5`) either. Gated the whole test behind
  `if (@sizeOf(usize) < 8) return error.SkipZigTest;`, a comptime-known condition Zig
  prunes at compile time (verified: the guarded shift compiles for `wasm32-wasi` and
  still runs — unskipped — on native 64-bit, 19/19). Compile-only; the guard changes no
  behaviour on any target the module actually ships on.
- **2026-08-18** — Portability fix: `serialize`/`deserialize` wrote/read every multi-byte
  wire field (`u32` lengths, `i64`/`f64` cells, `i128` `.decimal` cells) via
  `std.mem.toBytes`/`bytesToValue`, which use the host's *native* byte order —
  accidentally little-endian on every CI lane so far, but silently wrong (and silently
  self-consistent, since a same-process round-trip cannot detect it) against the doc
  comment's "Little-endian" claim on a big-endian host. Switched to explicit
  `std.mem.writeInt`/`readInt(..., .little)`; floats go through a bit-cast to a
  same-width integer first (the IEEE-754 bit pattern is host-independent, only its byte
  order is). Added a fixed golden byte vector — computed independently with Python's
  `struct.pack('<...')`, asserted byte-for-byte against `serialize`'s output — as the
  oracle a round-trip test cannot be; a same-process round-trip still passed under the
  old, buggy code even on `-Dtarget=s390x-linux-musl` (native-endian is self-consistent
  within one process regardless of what that native order is), while the golden vector
  test correctly failed there. Verified via `zig build test-dataset -Dtarget=s390x-linux-musl`
  actually **run** under `qemu-s390x` (not just cross-compiled): 19/19 pass. **Not a
  format change on little-endian hosts** — the wire bytes are byte-for-byte identical
  before and after this fix (the golden vector documents the *pre-existing* de facto
  byte layout, which the old native-endian code happened to already produce on every
  little-endian host); no existing little-endian-host payload (e.g. a consumer's cache) is
  invalidated.
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-09** — New module: Canonical in-memory columnar-typed table — the
  normalization seam between data sources and consumers.
