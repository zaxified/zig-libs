# bolt3 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-23** — **Changed (unreleased API, new on 2026-11-20) + fix (dead stack):** `RevocationStore.get(out: *[32]u8, index) bool` replaces `get(index) ?[32]u8` (the received secret went back through the caller's result slot); `out` is untouched when nothing covers `index` (tested). `insert` and `get` now run their hash walks under `shachain_burn`: unburned, the dead-stack probe (`src/stackprobe_test.zig`, new rows) found the received secrets 326 B deep. Never in a tag.
- **2026-11-21** — **NEW: `bolt3.commitment`, BOLT#3 commitment and HTLC transaction construction; `bitcointx` and `ripemd160` are now dependencies.** Scripts (funding, `to_local`, `to_remote` under option_anchors, anchors, offered / received HTLC, P2A shared anchor), fee and trimming arithmetic (`commitmentFee`, `htlcTxFee`, `htlcUntrimmed`), `buildCommitment` (BIP69+CLTV order, obscured locktime and sequence, option_anchors and zero_fee_commitments), `buildHtlcTx`, the BIP143 digests, `finalize` witness placement and `derSignature`. Tested against all signed transactions of Appendix C (16), F (9) and H (11).
- **2026-11-20** — **Public API addition:** `RevocationStore` (`insert(secret, index) InsertError!void`, `get(index) ?[32]u8`), the BOLT#3 Appendix D compact store of received per-commitment secrets (49 entries; a secret that does not derive the stored lower entries, or arrives out of order, is `InconsistentSecret` and leaves the store unchanged). Tested against all nine App D `insert_secret` sequences. `perCommitmentSecret` now runs through the shared private `deriveBits` walk (same output).
- **2026-10-09** — **BREAKING:** dead-stack rule (CONVENTIONS §2.1.1). `derivePrivateKey`, `deriveRevocationPrivateKey` and `perCommitmentSecret` take their secrets by `*const [32]u8` and return the result through a leading `out: *[32]u8` (`derivePrivateKey(out, basepoint_secret, per_commitment_secret) Error!void`, `deriveRevocationPrivateKey(out, revocation_basepoint_secret, per_commitment_secret) Error!void`, `perCommitmentSecret(out, seed, index) void`; `out` is zeroed on error). All three run their body under a stack burn (`src/burn.zig`, 32 KiB / 4 KiB); `src/stackprobe_test.zig` probes them in ReleaseFast.

- **2026-10-05** — Fixed: `derivePrivateKey` accepted a `per_commitment_secret` >= n and
  silently reduced it (k256 `combMulBase` reduces instead of refusing), although
  `Error.InvalidSecret` promises a canonical scalar and `deriveRevocationPrivateKey`
  refused the same bytes; it now returns `error.InvalidSecret` (regression test).
  Mutation run: 26 of 27 killed, 1 equivalent; 2 tests added (every input refusal
  of the four derivations, the fix's regression).


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
