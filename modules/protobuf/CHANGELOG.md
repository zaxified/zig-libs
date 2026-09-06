# protobuf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
