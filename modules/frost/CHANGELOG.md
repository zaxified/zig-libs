# frost — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-26** — Fix: the DKG parts (`dkg.part1` / `part2` / `part3`) now burn 64 KiB of stack after the call instead of the shared 32 KiB. Their frames reach 33-36 KB deep (measured with the new ReleaseFast stack probes), so the old burn left the deepest bytes of the call's stack, below the share and coefficient arithmetic, uncleared. The signing paths keep the 32 KiB burn. Plus killing tests from the 2026-11-25 delta mutation run.
- **2026-11-23** — **NO CONSUMER-VISIBLE CHANGE:** the dead-stack probe (`src/stackprobe_test.zig`) also applies the residue rule (`testkit.stackprobe.residueOf`) to its snapshots: a non-zero byte below a measured call's burn now fails it, whatever secret the needle model names or misses. Clean. Test only.
- **2026-11-21** — **New:** `frost.dkg` (`dkg.zig`): frost-core's distributed key generation — `part1` (Feldman commitment + Schnorr proof of knowledge, challenge `HDKG` = new `frost.hdkg`, DST `contextString || "dkg"`), `part2` (frost-core's package checks, proofs verified, shares out), `part3` (shares checked with `vssVerify`, signing share, group key, every verifying share), `verifyProofOfKnowledge`, with frost-core's error names and a `culprit` out-parameter; every part burns its stack. Tests: frost-core v3.0.0's published secp256k1 DKG vector, a 3-of-5 run signing with its output, bent proof/share refused, the count/identifier checks. The stack burn moved to an internal `burn.zig` (no behaviour change). Additive.
- **2026-11-21** — **Behaviour change:** `verifySignatureShare` checks that `comm_i` is `identifier`'s entry in `commitment_list` (the commitments the binding factors and group commitment are computed over); a different pair is now `error.InvalidCommitmentList` (an existing member) instead of being verified as given. **New:** `aggregateVerified(allocator, commitment_list, msg, group_public_key, sig_shares, verifying_shares, culprit)`: `aggregate`, then `verify`, and on failure the first share that fails `verifySignatureShare` is written to `culprit` with `error.InvalidSignatureShare` (`error.InvalidSignature` when every share verifies but the aggregate does not), as frost-core's `aggregate` does. New error set `AggregateVerifiedError`.
- **2026-11-21** — The internal `expand_message_xmd` (H1–H3) is now `sha2.expandMessageXmd` (new dependency `sha2`) instead of a local SHA-256 copy, which also drops its `std.debug.assert` on the DST length (undefined behaviour in ReleaseFast; the ciphersuite's DSTs are fixed and at most 32 bytes, so it was never reached). Outputs unchanged (RFC 9591 Appendix E.5 KATs).
- **2026-11-20** — **Behaviour change (build metadata):** `bip340` is no longer a declared dependency (`meta.deps` is `{"k256"}`, and the `build.zig` entry): no function of this module ever called into it, and the aggregate signature is not a BIP340 signature. A consumer that relied on `frost` pulling `bip340` into its build graph must name it itself.
- **2026-11-16** — **NEW:** `vssVerify(share, vss_commitment)` (RFC 9591 Appendix C.2 `vss_verify`) and `VssVerifyError`: a participant checks its dealer share against the Feldman commitment; `false` on mismatch/malformed/zero share, `error.InvalidParameters` only for an empty commitment. The secret share only enters `combMulBase`; commitments use the public multiplication. Tests against the E.5 vector and a t = 3 sharing.
- **2026-11-14** — tests: stale-audit mutation run over the code changed since the 2026-10-08 audit (37 mutants: 34 killed by the existing suite, 2 equivalent, 1 killed by the new test below): `round2Sign` with a zero hiding or binding nonce returns `IncorrectCommitment` (the commitment recomputation fails on the identity), which no test had pinned -- the error arm was swappable for `InvalidCommitmentList`. No source change.
- **2026-10-10** — tests: deterministic fuzz driver `FROST_FUZZ` (frost now has `testkit` in `test_deps`; the local seed/cursor copies in `kat_test.zig` are kept, see the note there): `frost-verify` (published signature with 0-40 octets replaced: the published one verifies, no other 65 octets do), new `frost-wire` (Element/Signature/scalar/Identifier decoders on damaged published values and uniform bytes; what is accepted re-encodes to the same octets) and new `frost-protocol` ((t,n) trusted-dealer keygen, drawn quorum, both rounds, aggregate, verify; a flipped signature bit, another message, a flipped bit of one signature share -- named by `verifySignatureShare`, and an `aggregate` over it is refused by `verify` -- are rejected). No source change.
- **2026-10-08** — **BREAKING + FIX (secrets in the caller's frame):** the dead-stack probe (`src/stackprobe_test.zig`) moved to the direct-region
  engine (p256's, 2026-10-08): the call runs under a `PAD`-deep shim, the region is painted and read
  through a pointer, callee-saved registers are scrubbed first. The old "claim an uninitialised
  buffer" engine could not see the top ~250–450 B of the call — the caller's and the wrappers'
  frames. It found the signing
  share in the caller's frame after `round2Sign` and `generateNonces`, and both nonces in
  `generateNonces`' own frame (by-value return held past the burn). `round2Sign(…, signing_share:
  *const SigningShare, …)`, `generateNonces(out: *SigningNonces, signing_share: *const
  SigningShare, …) void`. 0 residues after.
- **2026-10-08** — **FIX (secrets on the dead stack):** the dead-stack burn's buffer is now
  16-aligned instead of the vector type's natural 32. At 32 the burn's frame was realigned, and
  the up to 56 bytes between its saved frame pointer and the buffer — the top of the frame the
  burned body had used — stayed unzeroed (found by `threshold_ecdsa`'s stack probe: half of a
  secret survived there). No API change.
- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE (speed):** the dead-stack burn zeroes with
  volatile 32-byte vector stores instead of `std.crypto.secureZero` (a volatile byte memset,
  ~3 B/ns without libc): ~30× faster per KiB burned. Same size, same depth; the ReleaseFast stack
  probe still reads 0.
- **2026-10-08** — **BREAKING:** `round1Commit(nonces: *const SigningNonces)` and `round2Sign(…,
  nonces: *const SigningNonces, …)` take the nonce pair by pointer, as frost-core's `&SigningNonces`.
  Security (HIGH): `generateNonces`, `round1Commit` and `round2Sign` left the signing share and the
  secret nonces on the dead stack — measured with the new `src/stackprobe_test.zig` (ReleaseFast) —
  and a nonce next to the published signature share is the share. Each now runs its work one
  `noinline` frame down and burns 32 KiB after it; the by-value pair was copied at the call
  boundary, outside any burn, hence the pointer. Migration: pass `&nonces`.
- **2026-10-08** — **BREAKING (error set):** `round2Sign` checks RFC 9591 §5.2's MUST that
  `commitment_list` carries this signer's own round-1 commitments (`nonces·G`), as frost-core's
  `sign` does: new `Round2SignError.IncorrectCommitment` when the listed hiding or binding
  commitment differs (a Coordinator could otherwise choose this signer's part of `R`);
  `InvalidCommitmentList` when the identifier is absent. An exhaustive `switch` over the error set
  needs the new arm. `trustedDealerKeygen` refuses `min_participants < 2` (RFC 9591 Appendix C.1;
  a threshold of 1 hands every participant the group secret) and zeroes the shares before freeing
  them on an error path. ctgrind `sign` 5 → 13 (the commitment recomputation and comparison).
  Audit 2026-10-08 (`SPEC.md`).



- **2026-09-07** — Test-only, no production change: `fuzzVerify`, the harness named "never
  panics on **corrupted** signature bytes", had never corrupted a byte. Its first draw was
  `smith.valueRangeAtMost(u8, 0, 6)` and it had no corpus, so `n_flips` was the range
  MINIMUM - **0** - on every input the ordinary lane ever ran: it verified the pristine
  RFC 9591 Appendix E.5 signature, unmodified, every round. Two things were wrong and
  fixing one would have bought nothing. (1) The draw: the perturbation script now comes out
  of one `smith.slice` read through `testkit.fuzz.Cursor`, so the byte draw is first and a
  seed is a readable `[flip count][position, value]...` script. (2) The flip BUDGET: the
  harness's own comment says the mutation lands "near the `Element`/`Scalar` canonical-range
  boundary", but secp256k1's `n` is `FFFFFFFF...FFFFFFFE BAAEDCE6...` - **fifteen leading
  0xFF octets** - so no edit of six octets can raise a 32-octet scalar above it, and
  `Scalar.fromBytes`'s range check could not have fired from this harness at any flip count
  it was able to draw. The cap is now 40 and one seed spends sixteen flips on exactly that
  refusal. Measured by the new `corpus:` guard: 7 non-empty scripts, **29 flips applied**
  (0 before), 6 signatures parsed, 2 verified - so four corrupted signatures got past
  `fromBytes` and were refused by the group equation, the path the target exists for.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `verify` (corrupted signature bytes against the fixed RFC 9591 Appendix E.5
  group public key/message) — `zig build check-fuzz` no longer names this
  module. No panic/OOB found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9591 Appendix
  E.5's published test vectors.
- **2026-07-12** — New module: FROST — Flexible Round-Optimized Schnorr Threshold
  signatures (RFC 9591), secp256k1/SHA-256 ciphersuite — a t-of-n threshold Schnorr
  scheme: trusted-dealer keygen (Shamir + Feldman VSS), 2-round.
