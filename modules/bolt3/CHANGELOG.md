# bolt3 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **derive 7 / revocation 10 / shachain 0 / shachain_index 1**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. `SPEC.md`'s "No secret-dependent branching beyond `std.crypto.ecc`'s constant-time scalar ladder" is confirmed: every context in `derive`/`revocation` is one of two already-accepted classes (scalar canonicality, `rejectIdentity`), all disassembled. Settles an audit question: `perCommitmentSecret`'s branch on `index` is not a finding — BOLT #3 treats the commitment number as protocol state both peers already track, and `obscured_commitment_transaction_number` exists to hide it from chain observers, not from the peer. `shachain_index` is an honest positive control that taints the index deliberately, to prove the harness can see that branch at all. ⛔⛔ Instrument defect found here: a fully-inlined callee gets its merged frame reported at `root.zig:0` — never a real source line — and because the classifier matches PATTERN anywhere in the paragraph and BEFORE WITNESS, a bare `root[.]zig` filed two genuine propagation witnesses as in-file. It lies in both directions. The pattern for these two rows is `root[.]zig:[1-9]`.

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
