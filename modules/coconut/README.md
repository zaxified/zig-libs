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

> Public-attribute issuance (every authority sees every attribute); selective disclosure at show time
> is complete. The four cores — `signPartial`, `aggregateCredential`, `proveCredential`, `verifyCredential` —
> are implemented behind `gate.fable_core_implemented` (`true`). See `SPEC.md` for the construction, the full
> Fiat-Shamir transcript, the tier finding and the backlog.

## API

```zig
const coconut = @import("coconut");

// Setup + trusted-dealer threshold keygen (t-of-n over q attributes).
const p = try coconut.Parameters.generate(allocator, q);
defer p.deinit(allocator);
var keys: coconut.ThresholdKeys = undefined; // the secrets are written here, not returned
try coconut.keygen(&keys, allocator, io, q, t, n); // io: std.Io — draws fail closed
defer keys.deinit(allocator); // wipes the master key and every share

// Group verification key from any t vk shares (Lagrange-in-exponent) — REAL.
const vk = try coconut.aggregateVerificationKeys(allocator, keys.vk_shares[0..t]);
defer vk.deinit(allocator);

// The common signing base every authority derives from the public commitment.
const h = p.commonBase(&attributes);

// Fable cores (threshold-issue → aggregate → selective-disclosure show → verify):
const partial = try coconut.signPartial(&keys.sk_shares[j], h, &attributes); // the share by pointer
const cred    = try coconut.aggregateCredential(allocator, partials, t);
// `context` = the verifier's fresh nonce + its name; the proof answers only that.
const proof   = try coconut.proveCredential(allocator, io, p, vk, cred, &attributes, &disclosed, context);
defer proof.deinit(allocator);
// The verifier passes the mask IT asked for, not the one inside the proof.
const ok      = try coconut.verifyCredential(allocator, p, vk, proof, &disclosed, &disclosed_values, context);

// Blind issuance (paper §4.3): the authorities never see the private attributes.
var eg: coconut.ElGamalKeyPair = undefined;
coconut.elgamalKeyGen(io, &eg); // the user's key; eg.deinit() wipes d
var req = try coconut.prepareBlindSign(allocator, io, p, eg.gamma, &private_attrs, &public_attrs);
defer req.deinit(allocator);
// each authority j (checks the proof, error.InvalidProof otherwise):
const bs = try coconut.blindSign(allocator, &keys.sk_shares[j], p, eg.gamma, &req, &public_attrs);
const partial_j = coconut.unblind(&eg, &bs); // -> aggregateCredential as above; attributes = private ++ public

// Dealer-free key generation instead of `keygen` (frost-core's part1/2/3 shape,
// participants 1..n). Round-1 packages go over an authenticated broadcast
// channel, round-2 shares over confidential authenticated point-to-point ones.
var s1: coconut.dkg.Round1SecretPackage = undefined;
var r1 = try coconut.dkg.part1(allocator, io, &s1, my_index, n, t, q); // broadcast r1
var s2: coconut.dkg.Round2SecretPackage = undefined;
var culprit: u64 = 0; // the first sender whose package fails a check
const shares_out = try coconut.dkg.part2(allocator, &s2, &s1, received_round1, &culprit);
// send shares_out[k] to shares_out[k].recipient; free with dkg.freeRound2Packages
var my_share: coconut.SecretKeyShare = undefined; // -> signPartial / blindSign
var pub_pkg = try coconut.dkg.part3(allocator, &my_share, &s2, received_round1, received_round2, &culprit);
// pub_pkg.vk = the group key, pub_pkg.vk_shares = every authority's vk share
```

A show proof is bound to `context`: issue a fresh nonce per show and refuse a
nonce you have seen, or a recorded proof opens the door again. An empty context
binds nothing.

## Randomness

`keygen`, `dkg.part1` and `proveCredential` take `io: std.Io` and draw every secret scalar
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

Coconut has no published byte-exact vector for the show proof (`SPEC.md` §3; the
PS-signature core is cross-checked against a foreign library, see Provenance), so
no consumer needs a deterministic issuance. This module's own tests use
`keygenSeededForTest` / `proveCredentialSeededForTest`; the names are the
signal, and there is no seeded option on the production functions.

## Verify

```
scripts/modtest coconut
```

Provenance: clean-room from the Coconut NDSS 2019 paper (a public academic
publication, not a copyrightable implementation) — no third-party source ported
or studied as a design reference, so no `NOTICE` entry (CONVENTIONS §5, same as
`bbs`/`frost`/`dkg`). The reference implementations `asonnino/coconut` (Python)
and `nymtech/coconut` (Rust/Go) were consulted only black-box, to confirm no
public byte-exact test vectors exist (see `SPEC.md` §3). The committed test
vectors in `src/interop_vectors.zig` were observed from a third-party library
run as a black-box oracle: docknetwork/crypto's `coconut-crypto` 0.14.0
(Apache-2.0), driven by our own tooling (`tools/vectors/`); they are values it
computed from seeded inputs, no source of it was copied. Adds nothing to
`bls12_381`'s field/group/pairing math.
