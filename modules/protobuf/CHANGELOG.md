# protobuf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
