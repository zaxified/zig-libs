# isis-lsdb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
