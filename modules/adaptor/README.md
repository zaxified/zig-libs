# adaptor

Schnorr adaptor signatures ("one-time verifiably encrypted signatures",
the scriptless-scripts construction) over BIP340 Schnorr on secp256k1 —
the primitive behind PTLCs (point-time-locked contracts) in Lightning and
generic atomic swaps. Builds directly on the sibling `bip340` module for
tagged hashing, x-only key handling, and — crucially — the exact challenge
tag, so a completed adaptor signature is a plain, ordinary BIP340
signature indistinguishable from one produced by `bip340.sign` directly.

**Status: complete.** Wire codecs (`AdaptorPoint`, `PreSignature`) and the
four crypto cores (`preSign`, `preVerify`, `adapt`, `extract`) are all
implemented and KAT-validated — no `@panic`/TODO stub remains in
`root.zig`. See [SPEC.md](SPEC.md) for the design and the parity
subtlety this scheme's correctness hinges on.

| File | Contents |
|---|---|
| `root.zig` | `AdaptorPoint` (33-byte general point), `PreSignature` (65-byte pre-signature codec), and the 4 crypto cores (`preSign`, `preVerify`, `adapt`, `extract`) — all REAL |
| `kat_vectors.zig` | 6 self-authored reference vectors (no official BIP/spec exists for this scheme) — both `needs_negation` branches, both BIP340 key-normalization branches |
| `kat_test.zig` | Byte-exact KAT assertions + a round-trip property harness (`preVerify` accept, `bip340.verify` accept, `extract` round-trip) + tamper-rejection tests |

## Import

```zig
const adaptor = @import("adaptor");
const bip340 = @import("bip340");
```

## The four algorithms

```zig
// The adaptor point T = t*G — a GENERAL point (unlike bip340's x-only
// keys), 33-byte SEC1-compressed. Usually handed to you by a counterparty
// who knows t but isn't revealing it yet.
const t_point = try adaptor.AdaptorPoint.fromBytes(t_point_bytes);

// PreSign: bind a pre-signature to T, without knowing t.
const presig = try adaptor.preSign(sk, msg, aux_rand, t_point, io);

// PreVerify: anyone can check the pre-signature is well-formed for
// (pubkey, msg, T) — still without knowing t. Never panics/errors:
// false on every failure path (mirrors bip340.verify).
const ok = adaptor.preVerify(xonly_pubkey, msg, t_point, presig);

// Adapt: whoever knows t completes the pre-signature into an ORDINARY
// 64-byte BIP340 signature — verifiable by plain bip340.verify with no
// idea an adaptor scheme was involved.
const sig_bytes = try adaptor.adapt(presig, t_secret);
const sig = try bip340.Signature.fromBytes(sig_bytes);
const verified = bip340.verify(xonly_pubkey, msg, sig); // true

// Extract: whoever holds BOTH presig and the completed sig recovers t —
// the scheme's deliberate one-time key-leaking property.
const recovered_t = try adaptor.extract(presig, sig, t_point);
```

`PreSignature` (65 bytes: `r (32) ‖ s_prime (32) ‖ needs_negation (1)`)
carries an explicit parity-correction bit that a verifier cannot recompute
on its own — see `SPEC.md`'s "Parity" section for why.

## Import graph

```
adaptor → bip340 → std.crypto.ecc.Secp256k1 / std.crypto.hash.sha2.Sha256
```

## Verify

```
zig build test-adaptor                       # Debug — green
zig build test-adaptor -Doptimize=ReleaseFast # also green
zig fmt --check modules/adaptor/
```

`kat_test.zig` asserts byte-exact `preSign`/`adapt`/`extract` output
against all 6 self-authored `kat_vectors.zig` vectors, plus a
full-pipeline property test (`preSign → preVerify → adapt →
bip340.verify → extract`) and tamper rejection (wrong `T`, wrong message,
flipped `needs_negation`, mismatched nonce). No official BIP/spec test
vectors exist for this scheme — see `NOTICE` for how the vectors here
were generated and cross-validated.

Provenance: see [NOTICE](NOTICE).
