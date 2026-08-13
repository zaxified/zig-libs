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
const keys = try coconut.keygen(allocator, io, q, t, n); // io: std.Io — draws fail closed
defer keys.deinit(allocator);

// Group verification key from any t vk shares (Lagrange-in-exponent) — REAL.
const vk = try coconut.aggregateVerificationKeys(allocator, keys.vk_shares[0..t]);
defer vk.deinit(allocator);

// The common signing base every authority derives from the public commitment.
const h = p.commonBase(&attributes);

// Fable cores (threshold-issue → aggregate → selective-disclosure show → verify):
const partial = try coconut.signPartial(keys.sk_shares[j], h, &attributes);
const cred    = try coconut.aggregateCredential(allocator, partials, t);
const proof   = try coconut.proveCredential(allocator, io, p, vk, cred, &attributes, &disclosed);
defer proof.deinit(allocator);
const ok      = try coconut.verifyCredential(allocator, p, vk, proof, &disclosed_values);
```

## Randomness

`keygen` and `proveCredential` take `io: std.Io` and draw every secret scalar
through `Entropy.scalar` (`keys.zig`), which calls `bls12_381`'s
`Fr.random(io)`. That function is fail-closed: it draws through `entropy`'s
`fill`, i.e. `std.Io.randomSecure` or an abort, never `std.Io.random` (whose
own doc documents a silent fallback to a weaker seed if the CSPRNG source is
unavailable). This module reaches that posture transitively, through
`bls12_381`, without importing `entropy` itself — the `bbs`/`ibe`/`tlock`
shape, and stronger than a bare `std.Random.DefaultPrng` parameter, which is
why it matters here:

- A seed-derived master secret `(x, y₁…y_q)` lets anyone who recovers the seed
  issue arbitrary valid credentials for the entire system. The `t`-of-`n`
  threshold split becomes decoration, because the dealer's secret never had to
  be reassembled from shares.
- A witness nonce that repeats across two shows lets a verifier who sees both
  extract the hidden attributes and the blinding `r` by the standard
  two-transcript Sigma-protocol argument — the exact privacy selective
  disclosure exists to provide.

Coconut has no published byte-exact vector (`SPEC.md` §3), so no consumer needs
a deterministic issuance. This module's own tests use
`keygenSeededForTest` / `proveCredentialSeededForTest`; the names are the
signal, and there is no seeded option on the production functions.

`std.Io.randomSecure` is the fail-closed alternative to `std.Io.random`
(errors/aborts instead of degrading). Whether this module's secret draws
should fail closed was an open decision tracked in the project backlog; it is
now closed (`CONVENTIONS.md` §2.2) and, per the paragraph above, this module
already meets it — through `bls12_381`'s `Fr.random`, not by importing
`entropy` directly.

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
