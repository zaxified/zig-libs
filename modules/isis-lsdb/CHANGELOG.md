# isis-lsdb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-21** — **ADDITIVE (4 options, 1 query, 1 report field) + source-breaking type change:** (1) circuit limit lifted from 32 to 255: `max_interfaces` is 255 (the most a one-octet circuit index names) and `InterfaceSet` is a 256-bit set; the per-circuit SRM/SSN queues are allocated on first use. A caller that copied `InterfaceSet` into a `u32` or sized an array with the old `max_interfaces` must adapt. (2) LSPDBOverload (ISO 10589 §7.3.19): `Lsdb.isOverloaded()` becomes true when `insert` sheds a new LSP-ID with `error.DatabaseFull` and is cleared by `tick` after `Config.overload_recovery` (default 60) below capacity (`AgeReport.overload_cleared`); `Config.lspdb_overload = false` keeps it clear. (3) RFC 7987: `Config.lifetime_floor` (default 0 = off) raises the stored Remaining Lifetime of a received live LSP below it. (4) RFC 6232: `Config.purge_originator` (default false) adds a #13 TLV with our system id to a purge made by aging. Behaviour change: none with the defaults. 4 tests.
- **2026-11-19** — **ADDITIVE (option):** `Config.auth_snp: bool = true`. With `auth_keys` set, `false` makes `reconcileCsnpBytes`/`reconcilePsnpBytes` neither verify nor require a #10 on SNPs (FRR isisd's default, Junos `no-csnp-authentication`/`no-psnp-authentication`); the default `true` keeps the holo/Junos/IOS behaviour of 2026-11-18. LSPs unaffected. Behaviour change: none for existing callers. 1 test; delta mutation 5/5 (card 72/77).
- **2026-11-18** — **ADDITIVE (option, error set, two functions) + Behaviour change with keys only:** LSP/SNP authentication. `Config.auth_keys` (default empty = unchanged): `insert` verifies a received LSP's TLV #10 with `isis.auth.verify` before anything else (`error.AuthMissing` / `error.AuthFailed`), a received purge may carry only #10/#13/#137 (`error.InvalidPurge`, RFC 5304 §2 / RFC 6233), a verified purge is retained whole instead of header-only, an LSP aged out here becomes a purge signed with `auth_keys[0]` (checksum field kept), and new `reconcileCsnpBytes`/`reconcilePsnpBytes` verify an SNP before reconciling. `InsertError` gains three members: an exhaustive `switch` on it must add them. 12 tests; delta mutation 20/20 (card 67/72).

- **2026-10-18** — Ported to Zig 0.17.0. `IntegerBitSet.initEmpty()` -> `.empty`. Also: comptime `strRepeat` helper quota raised.
- **2026-10-10** — tests: deterministic fuzz driver `ISIS_LSDB_FUZZ`: `isis-lsdb-insert` (hostile LSP bytes, six arrival arms), `isis-lsdb-snp` (hostile CSNP/PSNP into a bounded store) and a new `isis-lsdb-sequence` update-process model (strictly higher sequence stored, equal/lower ignored, a received LSP naming us never stored, one flipped bit in the checksummed region refused and the store unchanged). No source change.
- **2026-10-05** — Mutation run: 47 of 52 killed, 5 equivalent; 9 tests added and one
  KAT extended (purge vs purge; same/older arrival acks; own-LSP echo, challenge SSN
  withdrawal and monotone `challenge_sequence`; own SNP ack; CSNP completeness incl. a
  malformed CSNP and placeholders; all-zero SNP entry and full store; placeholder fill
  and budget return; refresh threshold; aged-purge lifetime and `srmIsSet` bound). No
  code change.
- **2026-09-07** — **Both fuzz harnesses fixed: `fuzzInsert` had only ever been
  handed an empty slice, and every knob in it was structurally stuck on one side.**

  `fuzzInsert` opened with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u8, 0, buf.len)`. `bytes` consumes `min(buf.len, in.len)`
  octets and a ranged draw then reads eight *more* as a little-endian u64, returning
  the range minimum when fewer remain — so `len` was 0 for every input a seed can
  carry, and `insert` was handed a slice `header.decode` refuses on its first line.

  ⭐ Worse than the empty slice: all three of the harness's knobs were
  `smith.value(bool)` draws made *after* that byte draw, so with the input exhausted
  every one of them was **false**. The LSP-header bias never ran. The checksum was
  never stamped. And `arrival` was always `null` — a **local origination**, which is
  explicitly exempt from the §7.3.14.2 checksum gate. The receive path, the only
  untrusted one and the reason this module has receive-side self-defence at all, had
  never been entered by the harness whose comment describes both sides of that gate.
  The three arms and the two arrival kinds are now enumerated, not drawn, so all six
  run on every seed.

  `fuzzSnp` was already seeded, but with a `snpSeed` helper that hand-assembled
  little-endian u64 words so each scalar draw would land inside its range — a corpus
  whose four entries differed only in a 64-bit constant and that nobody could review.
  It now takes one `smith.slice` draw and reads its choices from a
  `testkit.fuzz.Cursor`, so a seed is a readable script (`04` LSPs, then five octets
  each, then the SNP's entries) and `check-fuzz-reach` is satisfied honestly rather
  than worked around.

  Measured 2026-09-07, before → after. `fuzzInsert`: **0 of 9 seeds non-empty → 8 of
  9**, 0 local inserts → 15, and **0 accepted on the receive path → 7**. `fuzzSnp`
  over its five scripts: 10 LSPs seeded, 13 LSP-Entry records carried, **13 request
  placeholders created**, 8 entries summarised, and both the CSNP and the PSNP arm
  taken. Every one of those is 0 under the degenerate script, which is kept as the
  last seed precisely so the "before" stays executable.

- **2026-09-03** — New: `srmIsSet(id, iface)`, the single-bit form of
  `srmSet(id).?.isSet(iface)`. The set-building form costs one hash lookup per
  circuit to read one bit, and `isis-flood.prune` asks the question once per
  tracked `(lsp, iface)` pair on **every** poll — 15 ms per prune over 28 672
  pairs at `interface_count = 32`. Two lookups now, whatever the circuit
  count. `false` for an LSP that is not stored, matching `srmSet`'s `null`,
  and pinned against `srmSet` for every circuit rather than assumed equal.
- **2026-08-11** — Security audit: the link-state database's update process was missing
  several ISO 10589 receive-side defences against an unauthenticated peer — a single SNP
  could permanently wedge the database, and a peer could purge or sequence-lock this
  node's own LSP; fixed (8 findings, including all 3 rated HIGH).
- **2026-07-24** — New module: IS-IS link-state database — store LSPs by LSP-ID, ISO
  10589 §7.3 newer-LSP comparison (seq → zero-lifetime → checksum), time-injected aging
  + MaxAge purge, per-interface SRM/SSN flag sets.
