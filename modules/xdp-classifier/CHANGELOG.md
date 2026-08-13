# xdp-classifier — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified: The real anchor is
  the CAP_BPF load-verify test (`classifier.zig:544`) that builds the program with live
  LPM+scratch maps and submits to the kernel verifier.
- **2026-07-15** — New module: XDP packet classifier for a LibreQoS-style edge shaper.
