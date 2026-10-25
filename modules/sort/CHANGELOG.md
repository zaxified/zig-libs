# sort — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-25** — New module: fast in-place sorting, ported from Rust 1.93.1's
  `core::slice::sort` — `unstable` (ipnsort, a drop-in for `std.sort.pdq`),
  `stable` / `stableBuffer` (driftsort, allocating like Rust or on caller
  scratch), `selectNth` (introselect, `O(n)` worst case), `asc` / `desc` /
  `bytesLess` comparators (byte strings eight bytes at a time). Verified
  against `std.sort.block` as the model (tests and the `SORT_FUZZ` driver,
  inputs against guard pages), with comparison counts identical to Rust's on
  the same input; a comparator that is not an order gets a permutation back.
