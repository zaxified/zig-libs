# iec62351 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`): `ber.writeHeader`'s multi-byte
  length branch shifted its `usize` `content_len` by a hardcoded `shift: u6`, which
  fails to compile on a 32-bit target where `Log2Int(usize)` is `u5`. Retyped `shift`
  as `std.math.Log2Int(usize)` — `content_len` is a genuine buffer-sized `usize`, so the
  shift-amount type should be derived from the target rather than hardcoded. Compile-
  only, identical semantics (shift amounts here are `8 * (n-1-i)` with `n <=
  @sizeOf(usize) + 1`, comfortably inside `u5`); no behavioural test added. Verified:
  `zig build portable-iec62351` and `zig build test-iec62351 --summary all` (120/120)
  both green.
- **2026-08-06** — Security audit: four findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit.
- **2026-07-23** — New module: IEC 62351 power-systems security — GOOSE/SV
  authentication (62351-6) over caller-supplied PDU bytes, MMS application
  authentication (62351-4), and the TLS profile requirements as a checkable policy.
