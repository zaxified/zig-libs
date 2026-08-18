# loopix — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`), two test sites in
  `adversary.zig`: both looped a `u64` index to index the fixed test array `deps[i]`
  (and, in one case, `deps_sorted[i]`), which doesn't fit `usize`'s slice-index
  requirement on a 32-bit target — the `deps.len`/`deps_sorted.len` comparison bound is
  the actual TSV-flagged error. Neither loop var needed `u64` range (`tr`'s `arr`/`dep:
  Time` and `id: u64` params all widen implicitly from `usize`), so narrowed both to
  `usize`, matching the sibling test already written that way. Compile-only, identical
  semantics on every target that already built. Verified: `zig build portable-loopix`
  and `zig build test-loopix --summary all` (27/27) both green.
- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on Loopix (Piotrowska et al.,
  USENIX Sec 2017) / Nym — no interop KAT exists for the anonymity metric (design
  reference, not a test anchor).
- **2026-07-17** — New module: Loopix mixnet (Piotrowska et al., USENIX Security 2017 —
  Nym's design) — Poisson mix + cover traffic over Sphinx, model-checked in netsim
  against a global-passive-adversary anonymity invariant.
