# dkg

Secure **Distributed Key Generation** for [`threshold_ecdsa`](../threshold_ecdsa)
over secp256k1 — the **GJKR** construction (Gennaro, Jarecki, Krawczyk, Rabin,
*"Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"*,
J. Cryptology 2007), which removes the **trusted-dealer** assumption: `n` parties
jointly generate an ECDSA secret sharing with no party ever holding the whole
key and no dealer to trust.

GJKR is the *bias-resistant* DKG. Naive Pedersen-DKG lets a rushing adversary,
who waits to see honest parties' contributions before choosing its own, bias the
resulting public key. GJKR fixes this by a two-phase commit: parties first
commit to their sharings with **Pedersen** commitments and fix the qualified set
**QUAL** from complaints alone; only *after* QUAL is frozen do they reveal
**Feldman** commitments and extract the public key `Q = Σ_{i∈QUAL} g^{a_i0}`.

> **Status — scaffold; bias-prevention core GATED.** This Phase-1 pass ships the
> full mechanical layer (commitment helpers, wire codecs, the synchronous round
> driver, the invariant checkers, a `BrokenDkg` positive control, and the
> end-to-end anchor wiring) and leaves the five irreducible protocol-soundness
> functions in `core.zig` as `@panic` stubs behind
> `gate.fable_core_implemented`. The `BrokenDkg` positive control already gives
> the harness teeth with the core still stubbed (it accepts a Byzantine bad
> share, and the checker catches the resulting unusable key). Flip the gate once
> `core.zig` is implemented; the gated tests then enforce every correctness
> invariant and the decisive end-to-end anchor.

## The end-to-end anchor

There is no external byte-exact KAT for a randomized DKG, so correctness is
pinned a stronger way: the DKG-produced shares feed the REAL
`threshold_ecdsa.signWithShares`, and the resulting signature is verified under
the DKG's public key `Q` with **`std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`**.
A DKG that produces a valid, std-verifiable ECDSA signature produced a correct,
usable key — this defeats "self-consistent but nonstandard" without any external
vector. See the `END-TO-END ANCHOR` test in `src/root.zig`.

## Scope

**Phase 1 = the secret-key DKG only.** Output (`DkgShareOutput`) is the ECDSA
key material — this party's Shamir share `x_j`, the group key `Q = x·G`, and its
verifying share `X_j = x_j·G` — directly consumable by `threshold_ecdsa` signing
via `assembleKeyShares` (which attaches each party's independently-generated
Paillier keypair + ring-Pedersen aux params). Out of scope (later increments):
CGGMP21 signing-phase **identifiable abort**, **proactive refresh**, and a
distributed **aux-parameter** generation. See `SPEC.md`.

```zig
const dkg = @import("dkg");

// Run the dealer-free DKG (2-of-3), all parties honest.
const outs = try dkg.Dkg.run(allocator, .{ .t = 2, .n = 3 }, .{}, random);
defer allocator.free(outs);

// Every honest party agrees on Q, and any t shares reconstruct x with x·G == Q.
std.debug.assert(dkg.checks.allSameQ(outs));
std.debug.assert(try dkg.checks.reconstructsToQ(allocator, outs[0..2]));

// Bridge to threshold signing: attach Paillier + aux, then sign.
const key_shares = try dkg.assembleKeyShares(allocator, outs, 2, paillier_keys, aux_params);
```

Provenance: clean-room implementation of GJKR (J. Cryptology 2007) over
`std.crypto.ecc.Secp256k1`, reusing this repo's `threshold_ecdsa` key format /
Shamir+Feldman shape and `paillier`. No third-party code.
