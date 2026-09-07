# protobuf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
