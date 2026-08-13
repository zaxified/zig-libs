# isis-lsdb — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: the link-state database's update process was missing
  several ISO 10589 receive-side defences against an unauthenticated peer — a single SNP
  could permanently wedge the database, and a peer could purge or sequence-lock this
  node's own LSP; fixed (8 findings, including all 3 rated HIGH).
- **2026-07-24** — New module: IS-IS link-state database — store LSPs by LSP-ID, ISO
  10589 §7.3 newer-LSP comparison (seq → zero-lifetime → checksum), time-injected aging
  + MaxAge purge, per-interface SRM/SSN flag sets.
