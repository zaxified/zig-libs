# protobuf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — **PERFORMANCE, no API/behaviour change:** audit F6. `encodeAlloc` sizes every
  submessage exactly once (a `SizeTree` built in a throwaway arena over its own `gpa`) instead of
  recomputing a nested submessage's size once per level of nesting it is under, which made
  encoding a chain `depth` levels deep cost O(depth²). Measured (ReleaseFast, `smp_allocator`):
  depth 255 3.45ms -> 118µs (29x), depth 64 (the module's and `grpc.Stream.sendInner`'s own
  `max_depth` default) 213µs -> 31µs (6.9x). Trade-off, recorded honestly: for shallow messages
  (depth 1-4) the cache's own allocation overhead makes `encodeAlloc` measurably slower than
  before (hundreds of ns), crossing over to a net win around depth 8 — see SPEC.md "Not
  implemented" for the full numbers. `encodeInto` (the allocation-free path) is byte-for-byte
  unchanged, compiled identically to before; only `encodeAlloc`'s internals changed, no public
  signature or wire output changed anywhere.

- **2026-09-15** — **BEHAVIOURAL (new memory cap, on by default):** audit F1, round-2 decision
  Q4. Declared length and nesting depth were both bounded, but arena memory was not: a
  singular/optional message field that recurs many (`k`) times at many (`d`) levels of nesting
  is merged by concatenation (`decode.zig`'s `MergeBuf`), and that concatenation compounds with
  depth. Measured: a legal message 3.68 MiB on the wire (well under gRPC's own 4 MiB default
  `max_recv_message_size`) drove the decode arena to 501.4 MiB — 136×, scaling with `max_depth`.
  New `DecodeOptions.max_arena_bytes` (default 64 MiB, `default_max_arena_bytes`) bounds total
  bytes the decode arena may be granted; exceeding it surfaces as `error.OutOfMemory`, same as a
  real allocator exhaustion. A message that needed more than 64 MiB of arena to decode — legal
  but implausible outside this attack shape — now fails where it used to succeed. `grpc`
  (the only in-repo consumer) sets its own default to `frame.default_decode_arena_bytes` (8×
  `max_recv_message_size`, currently 32 MiB) on both the client (`Stream.receive`) and server
  (`Methods(..).Stream.receive`) sides, closing the gap end to end rather than leaving it opt-in.
  See `grpc`'s own changelog for that half. New regression test (`adversarial.zig`): a
  scaled-down version of the same shape (k=40, d=10, 16-byte leaf, <2 KiB wire) must fail under
  an 8 KiB budget while the identical bytes decode fine under the module default, and an honest
  single-occurrence chain of the same depth must fit the same tight budget — proof the guard
  targets amplification, not size.

- **2026-09-14** — **BEHAVIOURAL (aborts where it used to corrupt):** audit F8, round-2 decision
  Q2-B. The two-pass encoder's safety net — every `Emitter.byte`/`bytes` fits, and `encodeInto`/
  `encodeAlloc` filled the buffer exactly — was four `std.debug.assert`s. They do not exist in
  ReleaseFast or ReleaseSmall, where a size/emit disagreement wrote past the buffer and died with
  SIGSEGV. They are now `@panic(wire.size_mismatch_message)` in every build mode. No signature
  changes; no disagreement is known in the unedited encoder, so correct messages encode exactly
  as before. Measured cost (ReleaseFast, 1 024 varints + 3 strings, best of 7 rounds × 3 runs):
  8 207–8 260 → 8 327–8 359 ns/op, about 1–2 %. New test: a forked child overflowing a one-byte
  `Emitter` through `byte` and through `bytes` must abort with that message.

- **2026-09-11** — A1 fix campaign (F14, partial). **No consumer-visible
  change.** The main decode fuzz harness (`decode.zig`'s
  `fuzz: decode never panics or leaks...`) could only ever select 4 of the
  module's schema shapes (`Wide`/`Repeated`/`Keeps`/`Chain`) — `Presence`,
  the ONE shape with optional fields (`?i32`/`?[]const u8`, proto3
  explicit presence), was never reachable, so no amount of `--fuzz` time
  could exercise whatever `decode.zig` does differently for a nullable
  field's presence bit. Added as shape 4 (`conformance.presence_cases`
  seeded into the corpus, shape selector widened `u2 0..3` to `u3 0..4`).
  Not itself a fix for F14's plateau measurement (615345 runs, 7.17%
  coverage) — `--fuzz` is not in this campaign's permitted command set
  (`scripts/modtest` has no fuzz mode at all), so the percentage was not
  and could not be re-measured this pass — but a concrete, verified
  structural gap in what the harness could ever reach, closed. The
  harness's OTHER target (`fuzzDepthCapBoundary`, the audit's "only 15
  unique runs" observation) was reviewed and left alone: its 8 corpus
  seeds already cover every interesting boundary in its narrow 2D
  (`true_len`, `max_depth`) purpose by construction — a boundary-condition
  probe reaching few unique combinations is not itself a defect the way a
  general-purpose harness missing an entire schema shape is.
  **RED→GREEN (structural, not `--fuzz`):** `scripts/modtest protobuf`'s
  own corpus-count test used the single default draw to confirm the new
  shape is genuinely reached: `nonempty 37→41`, `accepted 33→38`,
  `octets 450→458`, all 5 shapes now hit (`shapes_seen` widened to
  `[5]bool`, every entry required true). `scripts/modtest protobuf`:
  74/74, unchanged count (widened an existing test, no new `test` block).
  Consumer `grpc`: `scripts/modtest grpc` 122/122, unchanged.

- **2026-09-11** — A1 fix campaign (F13). **No consumer-visible change** —
  new test coverage plus regenerated interop fixtures, no `src/` decoder or
  encoder logic touched.
  - **F13 (LOW):** `reference_interop.zig`'s successor
    (`conformance.zig`'s `semantic_cases` / `interop_replay_test.zig` /
    `tools/interop.zig`, restructured 2026-09-06) only ever asked the live
    Python reference about WELL-FORMED values; the two divergences
    `SPEC.md`'s "Smaller hardening" section calls "deliberately stricter"
    (a non-minimal tag, a field number above 2^29-1) were hand-typed claims,
    never actually checked against the reference. Extended `Expect` with a
    third case, `reject_stricter` (reference expected to ACCEPT; our
    decoder expected to reject with a named error — the opposite polarity
    from `reject_invalid_utf8`, where both sides reject), and a
    `referenceRejects(Expect) bool` helper so `tools/interop.zig`'s
    capture/live-check logic asks the right question for all three cases
    uniformly. Added two new `semantic_cases`, captured live against
    `google.protobuf` 4.21.12 (`zig build-exe` over `tools/interop.zig`
    directly, then `--capture`, since `zig build interop-protobuf` is a
    build-graph step this campaign's fixer lane does not run): a
    non-minimal tag on `Presence` (`90 00 05`) and an out-of-range field
    number on `Wide` (`80 80 80 80 10 00`, the same construction
    `wire.zig`'s own "F4 regression" test uses). **Both confirmed live: the
    reference ACCEPTS each, treats it as an unknown field, and re-serializes
    it byte-for-byte unchanged** — genuine divergences, not assumptions.
    **Also probed and NOT added:** the audit's own large-scale mutation
    campaign classified `VarintOverflow` (627 of 200000 mutated inputs) the
    same way, but a direct live check of the specific 11-byte shape
    `wire.zig`'s "an over-long varint is refused" test uses shows the
    reference REJECTS it too (`DecodeError: Too many bytes when decoding
    varint`) — no divergence for that particular shape, so it was not
    pinned as one; the audit's 627-count most likely spans a range of
    *different* overlong constructions this session did not reconstruct.
    `interop_replay_test.zig`'s count canary rewritten for the three-way
    split (reference-rejections vs. our-own-stricter-rejections vs. plain
    acceptances) rather than the old two-way one, which could not represent
    a case where the two sides' verdicts point in opposite directions.
    `scripts/modtest protobuf`: 74/74, unchanged count (both new cases
    exercised inside two already-existing tests, not new `test` blocks).
    Consumer `grpc` reverified: `scripts/modtest grpc` 122/122, unchanged.

- **2026-09-10** — A1 fix campaign, dojezd wave. **No consumer-visible change.**
  - **F10 (LOW, no behaviour change):** `emitMessage`'s own depth check
    (`if (depth >= options.max_depth) return error.DepthExceeded;`) was
    structurally unreachable — `encodeInto`/`encodeAlloc` always call
    `encodedSize` -> `messageSize` first, which enforces the identical bound
    at the identical depth before `emitMessage` is ever reached with it, and
    `emitMessage` is private so nothing else can call it directly. Removed,
    with a comment documenting the invariant instead of a second copy of the
    same check. Measured: 73/73 before and after removal (Debug and
    ReleaseFast) — unchanged, which is exactly what proves the branch was
    dead.
  - **F12 (LOW, test-only):** no float-pathology vector existed anywhere
    (NaN payload, +-Inf, denormal); `@bitCast` makes our encode/decode round
    trip bit-exact for these independent of any external oracle (the
    python reference is lossy here and was not needed). Added
    `codec_test.zig`'s "F12: float pathology (NaN payload, +-Inf, denormal)
    round-trips bit-exact" — 7 `f64` + 7 `f32` bit patterns compared by
    bits, not by `==` (NaN != NaN, so `expectEqual` on the float itself
    cannot express this case). `-0.0` excluded on purpose: `isDefault`
    treats it as the type default (`-0.0 == 0` in IEEE 754) and proto3
    implicit presence never puts it on the wire, so a round trip through
    an implicit-presence field cannot observe it either way. Measured:
    masking the sign bit off in `decode.zig`'s float/double branches fails
    4/74 tests (the new one plus two existing golden/interop cases that
    also carry `-1.5e300` — confirming the mask is load-bearing for
    existing coverage too); reverted after measurement, 74/74 (Debug and
    ReleaseFast).
  - F1/F6/F8/F13/F14 — still open; see
    `~/CML/20260901-zig-libs-audit/A1/protobuf.md`'s 2026-09-10 dojezd
    disposition for why each needs a decision or more budget than this
    pass had.
- **2026-09-10** — A1 fix campaign, wave-3 audit findings. **Consumer-visible: a `sint32`
  field's decoded value can change for a peer that sends a varint >= 2^32 (a bug fix — the
  old order disagreed with the reference above that threshold), and a new error
  `error.NonMinimalTag` can now surface from `decode` (a non-minimally encoded tag varint
  used to be read as the field it names; it is refused instead, closing a smuggling
  primitive — P1, input hardening, `grpc` propagates it through its existing catch-all
  `|| protobuf.DecodeError` union, no exhaustive switch to update).**
  - **F2 (HIGH):** `sint32` decode zigzagged on 64 bits and truncated to 32 *after* —
    the reference truncates to 32 bits *first*. The two orders agree below 2^32 and
    disagree above it. Fixed with a dedicated `wire.zigzagDecode32`. Measured: the
    regression test failed `expected 0, found -2147483648` against the old order,
    passes now (72/72).
  - **F3 (HIGH):** a non-minimally encoded tag varint (e.g. `90 00` for tag byte `10`)
    used to dispatch on the field NUMBER it decodes to, same as this module always has;
    the pure-Python reference dispatches on the tag's raw BYTES and never matches a
    known field for a non-minimal encoding, reading it as unknown instead (32/32 tested
    variants disagreed; for `proto3 optional` the disagreement is in *presence*, not
    just value). Now rejected with `error.NonMinimalTag`. A non-minimal *value* varint
    is untouched — that half of "Smaller hardening" stays parity with the reference, not
    a gap. ⚠ Checked against the pure-Python reference only; `upb` was not available to
    verify against and reportedly dispatches by field number, which would agree with the
    old behaviour — see SPEC.md. Measured: the regression test failed
    `expected error.NonMinimalTag, found explicit=5` against the old behaviour, passes
    now (72/72).
  - **F4/F5 (MED, test-only):** the length bound (`Cursor.take`) and the UTF-8 check
    were already correct in the tree — the audit's own mutations (`L4`: weaken the
    length bound to values under 2^40; `U3`: weaken UTF-8 validation to strings under
    64 bytes) proved that by surviving 69/69 green, because no test vector exercised
    either boundary. New vectors (declared lengths at 2^63 and u64::MAX; a UTF-8 error
    at offset 79 of an 80-byte string) close the gap. Measured: re-applying `L4` now
    crashes the suite (index-out-of-bounds panic, 71/72 + 1 crash); re-applying `U3`
    now fails it (71/72 + 1 leak). Both mutations reverted after measurement.
  - **F7 (MED):** `schema.infos`'s comptime duplicate-field-number check is O(n²) and
    hit `@setEvalBranchQuota`'s old budget (20 000) at exactly 29 fields —
    `evaluation exceeded 20000 backwards branches`, pointing into this module's own
    internals rather than the caller's schema. Raised to 2 000 000 (sized for a few
    hundred fields). Measured: a new 40-field message type fails to compile with that
    exact error at the old quota, compiles and round-trips at the new one.
  - **F9 (LOW, no behaviour change):** `Cursor.varint`'s 10-byte cap was enforced by an
    `i == 9` branch inside a `for (0..10)` loop that always returned, which made the
    loop's own upper bound unable to affect anything and left a `return
    error.VarintOverflow` after the loop that could never execute — mutating the loop
    bound (`10` -> `11`) was a silent no-op, and both mutations the audit aimed at that
    dead line survived 69/69 green. Refactored to read the first 9 bytes in a loop and
    the 10th explicitly after it: same semantics, no unreachable line, and the loop
    bound is now load-bearing. Measured: re-applying the audit's mutation (loop bound
    `9` -> `10`) on the new code now crashes 5 tests (integer overflow panic) instead of
    surviving; reverted after measurement.
  - **F11 (LOW, doc-only):** README's error list was missing `FieldNumberOutOfRange`
    (added by the 2026-08-06 wave) and `InvalidUtf8`; its test count ("65 tests") was
    already stale on top of that (73 after this wave, including `NonMinimalTag`'s three
    new tests, F4/F5's two, and F7's one). Both fixed.
  - F1 (HIGH), F6/F8/F10/F12/F13/F14 (MED/LOW) — left open; see
    `~/CML/20260901-zig-libs-audit/A1/protobuf.md`'s 2026-09-10 disposition for why each
    one needs a decision this fix pass could not make on its own, or costs more than
    this pass's budget covers.
- **2026-09-08** — **NO CONSUMER-VISIBLE CHANGE:** two of `fuzzDecodeNeverPanics`'s
  four knobs had no number on them. The corpus guard drew `copy_strings` and
  `reject_unknown_fields` to stay in step with the harness's word stream and
  then dropped them, so nothing pinned the seeds that turn the string-copy path
  and the unknown-field REFUSAL branch on — both are `false` on a tail-less
  seed. Measured and pinned: **38 of 40 seeds decode with `copy_strings`, 1
  with `reject_unknown_fields`.**

- **2026-09-07** — Test-only, no production change: both fuzz targets ran one input, and
  one of them had never executed the branch it exists to assert. `fuzzDecodeNeverPanics`
  drew `len = smith.valueRangeAtMost(u16, 0, 4096)` **before** the bytes; a ranged `Smith`
  draw returns the range MINIMUM unless a whole eight-octet word lands inside the range, so
  with no corpus `len` was 0 and `input` was the EMPTY slice on every round outside
  `--fuzz`. An empty protobuf message is legal for all four shapes, so the target had a
  100% acceptance rate while parsing nothing. `fuzzDepthCapBoundary` was worse: both its
  numbers were ranged draws with no corpus, so `true_len` and `max_depth` were **1 and 1**
  every time — it built a one-node chain, decoded it under a cap of 1, and took the success
  path. The `error.DepthExceeded` assertion this test was written for had never run once.
  Both now draw bytes first (`smith.slice`), the depth harness reading its two numbers
  through `testkit.fuzz.Cursor` so a seed is a readable pair. The decode corpus is the
  module's own `conformance.wide_cases` and `repeated_cases` encoded by its own encoder
  (arbitrary bytes essentially never spell a message: every length-delimited field needs a
  prefix that exactly covers what follows), plus `chain3` and the five hostile frames
  `adversarial.zig` names; each seed carries a `u64` tail so the four knobs after the byte
  draw are alive on a corpus replay rather than pinned at `Wide` with `max_depth = 1`.
  Measured by the two new `corpus:` guards — decode: 37 non-empty of 40 seeds, 33 accepted,
  **450 octets handed to the parser** (0 before), all four shapes and both sides of the
  depth cap exercised; depth boundary: 7 non-empty scripts, **2 above the cap** (0 before)
  and a deepest chain of **200** (1 before).

- **2026-09-06** — **The module no longer ships foreign source, and its test suite no
  longer needs `python3`.** `src/reference_interop.zig` (which `@embedFile`d a Python
  driver and spawned `python3 -c` from inside `test-protobuf`) and
  `src/testdata/reference.py` are gone from `src/`. The live comparison against the
  reference `google.protobuf` package is now a standalone program,
  `tools/interop.zig` + `tools/reference.py`, run by `zig build interop-protobuf` and
  compile-checked by `zig build check-interop`; it is never built by `test-protobuf`
  and never by `zig build`. Consumer-visible: a consumer of this module no longer
  vendors a Python file, and `zig build test-protobuf` runs 65 tests with **no skips**
  where it previously ran 69 with 9 skipped on any machine without the package
  (i.e. all of CI). What the anchor found is committed instead of re-derived:
  `zig build interop-protobuf -- --capture` writes `src/testdata/golden_bytes.zig`
  (the reference's encoder output for all 36 canonical cases — byte-identical to what
  was already committed) and the new `src/testdata/interop_vectors.zig` (the
  reference's parser verdict on the 8 byte strings a canonical encoder never emits:
  the packing flip, the two `MergeFrom` shapes, four invalid-UTF-8 `string` fields and
  the `bytes` control). New `src/conformance.zig` holds the message fixtures and case
  tables both sides share, exposed as `protobuf.conformance` solely so the
  out-of-tree program can reach them; it is not part of the codec API.
- **2026-08-06** — Security audit: four findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Live oracle, both directions,
  byte-exact.
- **2026-07-30** — New module: Protocol Buffers wire format (proto3) codec.
