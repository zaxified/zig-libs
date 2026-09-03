# isis-flood — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit. **`emitCsnp` no longer binary-searches its
  window.** `isis-lsdb.summarise` was given an ascending, tail-truncating
  contract, together with the pagination protocol a caller should use; this
  module was never updated and its code comments and `SPEC.md` went on citing
  the old hash order as the justification for narrowing the 64-bit LSP-ID
  space by halving. That cost ~64 extra full-database passes per window, per
  poll: measured over a 4096-LSP series, 991 `summarise` calls and 1.77 s
  against 16 calls and 28 ms for the same 16 windows — **62.7x**, enough at
  stock `complete_snp_interval` to starve the scheduler at ~12 circuits. The
  dependency on the sibling's ordering is now explicit: `emitCsnp` asserts the
  returned prefix is ascending, and a SIBLING CONTRACT test pins the property
  where it is depended on rather than only where it is declared.
- **2026-09-03** — **The CSNP tiling rule had no test that could tell it from
  the wrong rule.** `chunk_start = successor(previous chunk's last id)` could
  be replaced by `entries[i].lsp_id` with all 30 tests and all five Wireshark
  goldens green, because every chunking fixture used CONSECUTIVE LSP-IDs,
  where the two expressions are the same value. On sparse IDs they are not,
  and the gap they leave is a range advertised by nobody — a peer holding an
  LSP we lack in it never floods it back (ISO 10589 section 7.3.15.2 reasons
  over the advertised range, not the listed entries). A sparse-ID test now
  asserts the chunks abut and the series reaches the top of the space.
- **2026-09-03** — `lsp_entries_per_pdu` is **clamped at both ends**. The
  2026-08-23 entry below fixed the `== 0` fail-open with `@max(1, ...)`, but
  the assert it replaced guarded `1..=snp.max_entries_per_pdu`. Above the
  ceiling every `buildPsnp`/`buildCsnp` returns `ValueTooLong`, which both
  emitters report as `truncated` — "poll again immediately" on work that never
  gets smaller, i.e. a permanent zero-output livelock from a config typo, with
  no assert in ReleaseFast to catch it. Fixing the case and not the rule left
  half the gap open.
- **2026-09-03** — `emitPsnp` reports `truncated` when its 256-entry summary
  buffer caps the drain. It returned "not truncated", so `poll` computed
  `next_wakeup` as if nothing were pending and the caller slept up to
  `complete_snp_interval` with acks and requests outstanding — against
  `SPEC.md` section 6, which routes unpaced PSNP acks to the wakeup precisely
  via `truncated`. Reachable at stock settings: request placeholders are
  minted up to `request_capacity` (default `capacity / 4` = 1024).
- **2026-09-03** — **Per-circuit state is dropped when a circuit goes Down.**
  `csnp_primed[i]` was set on first sight and never cleared, so only the first
  adjacency ever seen on a circuit got its initial CSNP; every later one waited
  out the cadence. A flap mid-series also left `csnp_cursor[i]` parked, so the
  new neighbour's first CSNP advertised a window starting in the middle of the
  ID space. The pacing records for that circuit are dropped too — "we sent this
  recently" referred to a peer that is gone.
- **2026-09-03** — `prune` uses the new `isis-lsdb.srmIsSet(id, iface)` instead
  of building the whole per-interface set to read one bit, once per tracked
  pair, on every poll (measured at 15 ms per prune over 28 672 pairs at
  `interface_count = 32`). The determinism contract in both file headers is
  corrected to be stated over the lsdb **operation sequence**, not its state:
  LSP transmit order is `srm_queue`'s insertion order, so two stores with
  identical content built differently flood in different orders. `SPEC.md`
  also now records `partialSNPInterval` as a deliberate deviation rather than
  leaving it unmentioned.
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
