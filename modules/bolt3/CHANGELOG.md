# bolt3 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Licensing: `NOTICE` kind changed from `provenance note` (record only) to
  `third-party attribution` (carries a CONDITION). `src/root.zig` embeds BOLT#3's Appendix D and Appendix E test vectors verbatim from `lightning/bolts`,
  which is CC-BY 4.0, so attribution is owed and was not being given. ⛔⛔ The repository was
  distributing two opposite answers about one upstream: `lnwire`, `lninvoice` and `k256`
  record `lightning/bolts` as CC-BY 4.0 and attribute it, while this file said BOLT text is
  "not a copyrightable work (merger doctrine)" and needs no entry. Re-verified 2026-09-09
  against commit `152897261850d93c4f4597f39cf22d7d22d6ede6`: all 16 hex literals of 32+ characters that this module vendors appear verbatim in today's `03-transactions.md`. The pin is now that
  commit rather than "`master` branch", which is not a pin. CC-BY's
  indicate-modifications condition is discharged (none — the values are the published ones,
  hex-decoded). No code or data changed.

  The file already said the vectors are "reproduced byte-exact in the module's tests". That
  and "needs no attribution entry" cannot both be true of a CC-BY upstream.
- **2026-09-09** — `src/root.zig` gets its SPDX header (MIT). It was one of the two modules
  of 231 whose root file lacked one; the other was `brotli`, fixed in the same pass.

- **2026-07-18** — Security audit: no findings. Verified: Byte-exact vs BOLT#3 Appendix
  E (`derivePublicKey`/`derivePrivateKey`/
  `deriveRevocationPublicKey`/`deriveRevocationPrivateKey`, `root.zig:150-168`) and
  Appendix D.
- **2026-07-12** — New module: Lightning BOLT#3 key derivation — the commitment scheme's
  secp256k1 crypto pocket: per-commitment blinded keys (`basepoint + SHA256(pcp ‖
  basepoint)·G`, public + secret), the split-secret revocation.
