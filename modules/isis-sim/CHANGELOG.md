# isis-sim — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`): `Fabric.onTimer` indexed
  `self.failures.items[timer_id - fail_timer_base]` directly; `timer_id` is `u64`
  (`fail_timer_base = 1 << 32` is a tag bit distinguishing this timer class from
  `timer_poll`/`timer_restart`), which fails to compile as a slice index on a 32-bit
  target. The recovered index is bounded by `self.failures.items.len` — a
  scenario-authored list this same process appends via `failLinkAt`, never externally
  supplied — so it cannot reach anywhere near `usize`'s range without exhausting memory
  first; added a documented `@intCast` rather than widening the array, since the value
  genuinely cannot exceed a real `usize` in practice. Compile-only; no new behavioural
  test (the guard is unconditionally safe by construction, not a runtime boundary).
  Verified: `zig build portable-isis-sim` and `zig build test-isis-sim --summary all`
  (20/20) both green.
- **2026-08-06** — Security audit: five findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit.
- **2026-07-24** — New module: Headless multi-node IS-IS/SPB fabric convergence
  simulator.
