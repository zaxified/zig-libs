# isis-flood — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — Fixed a fail-open guard on `Config.lsp_entries_per_pdu`: `Scheduler.init`'s
  `std.debug.assert(cfg.lsp_entries_per_pdu >= 1 ...)` was the only thing keeping that
  caller-supplied value `>= 1`, and that assert is compiled out in ReleaseFast. With
  `lsp_entries_per_pdu == 0` and a non-empty database, `emitCsnp`'s chunker underflowed
  `entries[j - 1]` (`j == 0`) on its very first pass — a caught "integer overflow" panic in
  Debug/ReleaseSafe, and an out-of-bounds read (undefined behaviour, no bounds check to
  catch it) in ReleaseFast; `emitPsnp`'s sibling chunker instead spun `out.len` iterations
  emitting zero-entry PSNPs that never actually cleared SSN, starving the real ack. Fixed by
  clamping `per = @max(1, cfg.lsp_entries_per_pdu)` at both use sites, so the invariant holds
  unconditionally rather than depending on an elidable assert at construction time. Found
  while building `example/main.zig` (not by the example's own happy path, which never sets
  this to 0 — by reading the chunking loops while writing the example). Two new permanent
  regression tests in `scheduler.zig` construct the `Scheduler` directly (bypassing `init`'s
  guard, exactly as a ReleaseFast caller effectively can) and exercise both chunkers;
  mutation-verified: reverting the clamp reproduces the `emitCsnp` panic and the `emitPsnp`
  stall, `test-isis-flood` red in both Debug and ReleaseFast; restored, both green.
- **2026-08-06** — Security audit: with more than 256 LSPs in the database, the flooding
  scheduler's CSNP series claimed to cover the entire LSP-ID space while listing only
  256 entries, understating what a peer had actually seen; fixed, along with one further
  finding.
- **2026-07-24** — New module: IS-IS flooding transmit scheduler — drain `isis-lsdb`
  per-interface SRM/SSN flags into the ordered PDUs to send, pace LSP (re)transmission +
  emit periodic CSNPs; pure time-injected.
