# dnssec — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit. **The oracle's reproduction recipe is back in
  the repo.** `src/oracle_vectors.zig` — the module's strongest anchor, signed
  with `ldns-signzone` and independently accepted by `ldns-verify-zone` — was
  credited to `scratchpad/dnssec-oracle/`, which SPEC and README both named and
  README called "ephemeral". Accurately: a scratchpad does not survive a
  reboot, so the anchor had no re-takeable recipe at all, which makes it an
  assertion rather than a measurement (same shape as the drift-ranking script
  this campaign had to move out of a session scratchpad).
  `scripts/gen-dnssec-oracle.sh` restores the provenance chain: it builds a
  zone, signs it once per algorithm this module implements a verifier for
  (RSASHA256, ECDSAP256SHA256, Ed25519) plus an NSEC3 pass, and has ldns verify
  each — run and confirmed on this host, not written from memory. ⚠ It does
  NOT reproduce the committed vectors byte for byte (those keys are gone, and
  DNSSEC signatures are not deterministic across fresh keys), and the extractor
  that turned wire rdata into the `Vec` literals was only ever in the
  scratchpad and is not reconstructed. Both limits are stated in the script's
  own header and in SPEC rather than left for the next reader to discover.


- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).
