# montint — fast constant-time Montgomery modular arithmetic

`Modint(max_bits)` is a constant-time Montgomery big-integer type for modular
arithmetic over **arbitrary odd moduli** (prime *or* composite: RSA/Paillier
`N`, a VDF group order, a pairing-field prime). It is the native-Zig,
performance-competitive alternative to `std.crypto.ff` — same API shape
(`toMontgomery`/`fromMontgomery`, modular `add`/`sub`/`mul`, constant-time
`powMont`), designed to reach OpenSSL-competitive speed on amd64.

`std.crypto.ff` is portable and correct but stores 63-bit redundant limbs and
multiplies 4 half-limbs at a time, which forecloses the host's add-with-carry
and widening-multiply instructions — the measured cause of the ~8–29× gap vs
OpenSSL across this repo's `rsa`/`paillier`/`vdf`/pairing modules. `montint`
uses **full radix-2^64 limbs** so the amd64 `MULX/ADCX/ADOX` dual-carry-chain
Montgomery multiply (the OpenSSL `x86_64-mont5` technique) drops in, with a
portable CIOS fallback on every other architecture. Inline asm in Zig is still
native Zig — no libc, no C dependency — so the collection's zero-C invariant
holds.


## What is in the module

- `Modint(max_bits)` — the fixed-width Montgomery type used in the example below: comptime width, normal- and
  Montgomery-domain elements, `mul`, `add`/`sub`/`neg`, `eql`/`isZero`, constant-time `powMont` and `powMontBits`.
- `Field(p)` — GF(p) for a comptime prime, Montgomery-resident, with Fermat `inv`.
- `DynModint(max_bits)` — an odd modulus whose value and limb count are chosen at run time: constant-time
  `pow`/`powBits`, variable-time `powPublic`, `inverse`/`inverseOfModulus`, `sqrt` modulo a prime, `divExact`,
  Miller-Rabin `isProbablePrime`, element predicates and `compare`.
- `nt` — constant-time `gcd`/`lcm`/`oddPart`/`divExact` on limb arrays; `safegcd` — the batched divsteps engine behind
  `DynModint.inverse`.
- `asm_core`, `limbs`, `gate` — the asm kernels, the full-width limb helpers and the dispatch switch.

`SPEC.md` has the design of each.

## Dispatch

The portable CIOS runs on every target and is the correctness oracle: it is byte-exact against CPython bignum KATs at
256/512/2048/4096 bits. On x86-64 with ADX and BMI2 the `MULX/ADCX/ADOX` kernels take over from `L >= 16` limbs
(1024 bits) in the default build; below that — including the `bn254`/`bls12_381` pairing fields (L=4/6) — the
portable path is faster and stays. `-Dmontint-asm-unroll=false` (or `-Dprofile=small`) swaps the per-`L` kernels for
one looped kernel: far less code, slower modexp. See `SPEC.md` "Small-L dispatch" for the kernels and the figures.

## Usage

```zig
const montint = @import("montint");

// A 2048-bit odd modulus (prime or composite), from big-endian bytes.
const M = montint.Modint(2048);
const m = try M.fromBytesBE(modulus_be);

const a = try m.elementFromBytesBE(a_be); // reduced normal-domain element < m
const b = try m.elementFromBytesBE(b_be);

const prod = m.mul(&a, &b);      // (a·b) mod m, normal domain
const sum  = m.add(&a, &b);      // (a+b) mod m
const powr = m.powMont(&a, &e);  // a^e mod m, constant-time in e (5-bit window)

// Montgomery-resident work (convert once, stay in the domain across ops):
const am = m.toMontgomery(&a);
const r  = m.montMul(&am, &b);   // a·b (result normal-domain here)
const back = m.fromMontgomery(&m.toMontgomery(&a)); // == a
```

`Modint(max_bits)` fixes `L = ceil(max_bits/64)` full-limb width at comptime;
the modulus must be odd and ≥ 3. Elements are `[L]u64` little-endian; the domain
(normal vs Montgomery) is tracked by naming convention.

> **The byte loaders are the one part that is not constant-time.**
> `fromBytesBE`/`elementFromBytesBE` skip zero bytes, so the work depends on the
> input's byte values. Use them for PUBLIC encodings (a modulus, a validated
> group element). To load secret material, build the limbs branchlessly and go
> through `fromElem` — `rsa` and `paillier` both do exactly that. See
> [`SPEC.md`](SPEC.md) § "Constant-time contract".

## Verify

```
scripts/modtest montint                                  # Debug tests
zig build test-montint -Doptimize=ReleaseFast --summary all
MONTINT_BENCH=1 zig build test-montint -Doptimize=ReleaseFast  # opt-in ns/op bench
scripts/checks/ctgrind.sh montint --check                # constant-time measurement
```

The suite includes the byte-exact modmul+modexp KATs at 256/512/2048/4096 bits, the asm-vs-portable differentials, the
BrokenMont positive control (a dropped conditional-subtract, flagged RED), the Karatsuba==schoolbook mutual anchor, and
the CT-boundary checks; the one skip is the opt-in bench. Speed against OpenSSL: the card's `**Performance:**` line in
`SPEC.md` is authoritative. The win over `std.crypto.ff` is mostly the full-limb Montgomery-resident portable CIOS; the
asm kernels add the rest from 1024 bits up.

## Not provided

No Baillie-PSW primality test (Miller-Rabin only), no aarch64 asm core (arm64 runs the portable path), no
constant-time byte loaders (see the note under Usage), no blinding or fault countermeasures (this is a primitive, not a
signing scheme). See `SPEC.md` § What is deliberately not done and § Backlog / deferred.


Provenance: clean-room from public algorithm descriptions. The portable CIOS
Montgomery multiply is clean-room from Koç, Acar & Kaliski, "Analyzing and
Comparing Montgomery Multiplication Algorithms" (IEEE Micro 1996), Fig. 6, and
the API shape follows `std.crypto.ff` (Zig std, MIT). Design references,
behavior/algorithm only, no source copied: OpenSSL
`crypto/bn/asm/x86_64-mont5.pl` (**Apache-2.0**; the `MULX/ADCX/ADOX`
dual-carry-chain amd64 Montgomery-multiply technique the asm core
mirrors) and Gueron & Krasnov, "Fast Prime Field Elliptic Curve Cryptography with
256-Bit Primes" (the published description of the same two-independent-carry-chain
method). Test-vector cross-check only, not a design reference: the modmul/modexp
KATs at 256/512/2048/4096 bits were independently recomputed with CPython's
arbitrary-precision integers (`(a*b)%m`, `pow(a,e,m)`) — the same black-box
oracle method the `vdf` module uses — numerically identical to OpenSSL
`BN_mod_mul`/`BN_mod_exp`. No source ported. DATA: the KATs in `src/kat_vectors.zig` are CPython's answers (`(a*b)%m`, `pow(a,e,m)`) on moduli and operands we generated from a stated seed — a black-box oracle's output on our own input, exempt per root `NOTICE` §0. No third-party vector file is reproduced.
