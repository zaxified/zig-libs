# isis-lsdb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
