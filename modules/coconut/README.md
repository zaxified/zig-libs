# coconut

**Coconut threshold-issuance selective-disclosure anonymous credentials** over
`bls12_381` (Sonnino, Bano, Al-Bassam, Danezis — "Coconut: Threshold Issuance
Selective Disclosure Credentials with Applications to Distributed Ledgers", NDSS
2019 — the credential layer of Nym).

A set of `n` authorities each hold a Shamir share of a Pointcheval-Sanders (PS)
secret key. Any `t` of them independently issue a partial credential on an
attribute vector; the user aggregates `t` partials — Lagrange-**in-exponent** —
into one short, re-randomizable PS credential, then later **shows** it to a
verifier while revealing only a chosen subset of attributes in zero knowledge
(the credential itself and the undisclosed attributes stay hidden, and repeated
shows are unlinkable).

> **Status: Phase 1 — COMPLETE.** The mechanical layer (pairing/curve plumbing,
> threshold keygen, Lagrange-in-exponent verification-key aggregation, wire
> codecs, and the `psSignWithSecret`/`psVerifyPlain` PS oracles) is real and
> tested. The four irreducible cores — `signPartial`, `aggregateCredential`,
> `proveCredential`, `verifyCredential` — are implemented behind
> `gate.fable_core_implemented` (now `true`). The end-to-end anchor
> (threshold-issue → aggregate → show → verify) PASSES and the NIZK-soundness
> controls (tampered credential/κ/ν/σ', mutated challenge, wrong disclosed
> value, forged undisclosed attribute) all REJECT; the `BrokenCoconut` positive
> control and every mechanical unit test also pass. See `SPEC.md` for the
> construction, the full Fiat-Shamir transcript element list, the
> Fable-vs-mechanical split, the tier finding, and the deferred increments.

## API

```zig
const coconut = @import("coconut");

// Setup + trusted-dealer threshold keygen (t-of-n over q attributes).
const p = try coconut.Parameters.generate(allocator, q);
defer p.deinit(allocator);
const keys = try coconut.keygen(allocator, prng.random(), q, t, n);
defer keys.deinit(allocator);

// Group verification key from any t vk shares (Lagrange-in-exponent) — REAL.
const vk = try coconut.aggregateVerificationKeys(allocator, keys.vk_shares[0..t]);
defer vk.deinit(allocator);

// The common signing base every authority derives from the public commitment.
const h = p.commonBase(&attributes);

// Fable cores (threshold-issue → aggregate → selective-disclosure show → verify):
const partial = try coconut.signPartial(keys.sk_shares[j], h, &attributes);
const cred    = try coconut.aggregateCredential(allocator, partials, t);
const proof   = try coconut.proveCredential(allocator, prng.random(), p, vk, cred, &attributes, &disclosed);
defer proof.deinit(allocator);
const ok      = try coconut.verifyCredential(allocator, p, vk, proof, &disclosed_values);
```

Randomness (keygen blinding, show nonces) is a caller-supplied `std.Random`, so
a seeded PRNG makes issuance and show deterministic in tests — the
`bbs`/`frost`/`ibe` convention.

## Verify

```
zig build test-coconut                     # Debug
zig build test-coconut -Doptimize=ReleaseFast
```

Provenance: clean-room from the Coconut NDSS 2019 paper (a public academic
publication, not a copyrightable implementation) — no third-party source ported
or studied as a design reference, so no `NOTICE` entry (CONVENTIONS §5, same as
`bbs`/`frost`/`dkg`). The reference implementations `asonnino/coconut` (Python)
and `nymtech/coconut` (Rust/Go) were consulted only black-box, to confirm no
public byte-exact test vectors exist (see `SPEC.md` §3). Adds nothing to
`bls12_381`'s field/group/pairing math.
