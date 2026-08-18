# dataset — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
  little-endian host); no existing little-endian-host payload (e.g. a wgs cache) is
  invalidated.
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-09** — New module: Canonical in-memory columnar-typed table — the
  normalization seam between data sources and consumers.
