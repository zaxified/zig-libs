# reconcilable — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC statements that Zig has no io-less blocking mutex / `std.Thread` primitives re-checked against the 0.17.0 std (still true).
- **2026-10-18** — Ported to Zig 0.17.0. `assertPlainKey` iterates `field_types` of struct/union. Also: comptime `strRepeat` helper quota raised.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Kubernetes
  controller-runtime `workqueue` + `DelayingInterface` (design ref, documentation only)
  (design reference, not a test anchor).
- **2026-07-30** — New module: Generic desired-vs-actual reconciler (controller-runtime
  shape, clean-room from its docs).
