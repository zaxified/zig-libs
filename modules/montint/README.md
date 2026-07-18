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

## Status: IMPLEMENTED (amd64 asm core live)

The **portable path is real, constant-time, and byte-exact** against an
independent CPython-bignum oracle at 256/512/2048/4096 bits — it is the
correctness oracle. The irreducible amd64 asm core (`asm_core.montMul`, the
`MULX/ADCX/ADOX` dual-carry-chain CIOS) is **implemented and switched on**
(`gate.asm_core_implemented = true`): on x86-64+ADX+BMI2 the asm-vs-portable
differential harness runs live (5000 random 2048-bit cases + an `n`-sweep across
`{1,2,3,4,5,8,16,17,32,33,64}` limbs incl. leading-zero-limb moduli and squaring
aliasing, all bit-exact), and `montMul` dispatches to it for large moduli.

**Small-L dispatch:** the asm core is ~2.4× slower than the comptime-unrolled
portable CIOS at 256-bit and only wins from ~2048-bit up (`SPEC.md`
"256-bit regression"), so `montMul` routes to it only when
`L >= asm_min_limbs` (= 32, ≥2048-bit). Every smaller modulus — **including the
`bn254`/`bls12_381` pairing fields (L=4/6)** — stays on the faster portable path.
See `SPEC.md` for the full zig-vs-OpenSSL table.

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

## Verify

```
zig build test-montint --summary all                      # Debug
zig build test-montint -Doptimize=ReleaseFast --summary all
MONTINT_BENCH=1 zig build test-montint -Doptimize=ReleaseFast  # opt-in ns/op bench
```

16 pass / 1 skip (Debug and ReleaseFast on amd64+ADX+BMI2). The one skip is the
opt-in bench; the asm-vs-portable differential now runs. The suite includes the
byte-exact modmul+modexp KATs at 256/512/2048/4096 bits, the live asm-vs-portable
differential, the BrokenMont positive control (a dropped conditional-subtract,
flagged RED), the Karatsuba==schoolbook mutual anchor, and the CT-boundary
checks.

Measured this host (Kaby Lake, ReleaseFast; full table in `SPEC.md`), shipped
path vs OpenSSL 3.5.5 full-width: **2048-bit modmul 1.32× OpenSSL** (1.46 µs asm
vs 1.11 µs), **2048-bit modexp 1.79× OpenSSL** (3.43 ms asm vs 1.91 ms), and
montint *beats* OpenSSL at 256-bit — versus the 8–29× the `std.crypto.ff`-backed
modules pay. The win is mostly the full-limb Montgomery-resident portable CIOS
(ff→portable ~3.2× at 2048 modexp); the asm core adds ~1.5× on top.

Provenance: clean-room from public algorithm descriptions (Montgomery CIOS; the
OpenSSL `x86_64-mont5` `MULX/ADCX/ADOX` technique studied as a design reference;
`std.crypto.ff` API shape). KAT vectors from an independent CPython-bignum
re-derivation. See the `NOTICE` entry.
