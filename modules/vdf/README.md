# vdf

A pure-Zig **Verifiable Delay Function** (Wesolowski's RSA hidden-order-group
construction): `eval(N, x, T)` computes `y = x^(2^T) mod N` by `T`
**sequential** modular squarings — no shortcut, not even with unbounded
parallel hardware, unless you know `N`'s factorization (see "Trusted-setup
caveat" below) — and a succinct proof `π` lets anyone else check `y` is
correct in time independent of `T`. This is the "proof of elapsed time"
primitive behind randomness beacons and delay-based leader election.

**Status: COMPLETE.** The group arithmetic, the sequential delay itself
(`eval`), the Fiat-Shamir challenge-prime derivation (`hashToPrime`, with its
own Miller-Rabin), the mechanical half of verification (`pow2Mod`), and the
proof codec are real and tested — as are the two irreducible cores, `prove`
(the streaming-quotient Wesolowski prover) and `verify` (the `π^l·x^r == y`
soundness check). See [SPEC.md](SPEC.md).

```zig
const vdf = @import("vdf");

// The group: Z_N* for the RSA-2048 Factoring Challenge modulus (factorization
// unknown to everyone — see SPEC.md before using a different N).
const m = vdf.group.rsa2048ChallengeModulus();

// x as a canonical big-endian element.
var x_bytes: [vdf.group.modulus_bytes]u8 = [_]u8{0} ** vdf.group.modulus_bytes;
x_bytes[x_bytes.len - 1] = 5;
const x = try vdf.group.elementFromBytes(m, &x_bytes);

// eval: the delay itself — T sequential squarings.
const t: u64 = 1_000_000;
const y = vdf.eval(m, x, t);
var y_bytes: [vdf.group.modulus_bytes]u8 = undefined;
try vdf.group.toBytes(y, &y_bytes);

// prove: the succinct proof (streaming-quotient π = x^⌊2^T/l⌋ mod N).
const proof = try vdf.prove(m, &x_bytes, &y_bytes, t);
// verify: checks y in time independent of T (π^l · x^r == y mod N).
const ok = try vdf.verify(m, &x_bytes, &y_bytes, proof, t);
```

- `group.rsa2048ChallengeModulus()` — the RSA-2048 Factoring Challenge
  modulus (2048 bits), this module's zero-trusted-setup reference group.
- `group.elementFromBytes(m, bytes)` — decode + validate an untrusted
  big-endian group element (rejects `0`, `N`, and anything `>= N`).
- `eval(m, x, t) Fe` — `y = x^(2^t) mod N`, `t` sequential squarings. REAL.
- `hashToPrime(n_bytes, x_bytes, y_bytes, t) [32]u8` — the deterministic
  Fiat-Shamir challenge prime `l` both `prove` and `verify` derive from the
  same public binding. REAL (SHAKE256 candidate derivation + a
  deterministically-seeded Miller-Rabin — see [SPEC.md](SPEC.md) for why
  determinism, not just correctness, is the load-bearing property here).
- `pow2Mod(l_modulus, t) Fe` — `2^t mod l`, the cheap mechanical half of
  `verify`'s soundness check. REAL.
- `Proof` — `{ pi: [256]u8 }` plus `toBytes`/`fromBytes`. REAL.
- `prove(m, x_bytes, y_bytes, t) !Proof` — **FABLE CORE.** `π =
  x^⌊2^t/l⌋ mod N` via the streaming long-division quotient (no big-int;
  one dividend bit per squaring). See `vdf.zig`'s doc comment for the exact
  algorithm.
- `verify(m, x_bytes, y_bytes, proof, t) !bool` — **FABLE CORE.** Accepts
  iff `π^l · x^r == y (mod N)` with `r = 2^t mod l`; the `hashToPrime`
  binding includes `y` (soundness crux). Malformed/out-of-range inputs
  return `false`, never UB. See `vdf.zig`'s doc comment for the relation.

## Trusted-setup caveat — read before choosing a different `N`

This module takes `N` as a parameter; it does not enforce that `N`'s
factorization is unknown. The RSA-2048 Factoring Challenge modulus
(`group.rsa2048ChallengeModulus`) is safe to use with zero additional trust
— it was a public factoring challenge, 1991-2007, RSA-2048 was never
factored or claimed, and it is not known to anyone. A caller-supplied `N`
gets none of that for free: whoever generated it (or anyone who later
factors it) can skip the delay entirely by computing `2^T mod λ(N)`. See
[SPEC.md](SPEC.md) for the full explanation and the class-group alternative
(no trusted setup at all, out of scope here).

## Import graph

```
vdf → std.crypto.ff (Modulus/Fe), std.crypto.hash.sha3 (Shake256),
      std.crypto.hash.sha2 (Sha256), std.math.big.int (TEST-ONLY: the
      naive-quotient reference the streaming prover is cross-checked
      against — never on the shipped prove/verify path)
```

No sibling-module dependency (`meta.deps = .{}`) — see `root.zig`'s
`meta.deps` doc comment for why, despite `rsa`/`paillier`/`threshold_ecdsa`
each having conceptually similar pieces (a `Modulus`/`Fe` alias, a private
Miller-Rabin helper).

## Verify

```
zig build test-vdf                              # Debug — all pass, no skips
zig build test-vdf -Doptimize=ReleaseFast        # all pass, no skips
zig fmt --check modules/vdf/
```

`prove`/`verify` are exercised by completeness (`verify(prove(eval))`
accepts, several `(x, T)`) and soundness (wrong `y`/`π`/`T`, and every one
of `x`/`y`/`π` out of range → reject) tests, plus a naive-vs-streaming
big-int cross-check of the quotient across the `q=0`/`q=1` boundaries. No
published third-party RSA-Wesolowski `(N,x,T)→(y,π)` vector exists (all
public refs are class-group, not RSA `Z_N*`), so verification is property +
soundness rather than a byte-exact third-party oracle. `eval` and
`hashToPrime` ARE verified against byte-exact reference vectors computed
independently in Python (see `kat_test.zig`'s module doc comment for
exactly how, and how to regenerate them); `eval` additionally has an
independent-FORMULA cross-check via a factorization-known toy modulus
(Euler's theorem shortcut vs. sequential squaring). See
[SPEC.md](SPEC.md) for the full verification methodology and the honest
assessment of what remains Fable-hard.

Provenance: see [NOTICE](NOTICE).
