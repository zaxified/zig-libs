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

## Status: SCAFFOLD

The **portable path is real, constant-time, and byte-exact** against an
independent CPython-bignum oracle at 256/512/2048/4096 bits — it is the
correctness oracle. The irreducible amd64 asm core is a **gated stub**
(`gate.asm_core_implemented = false`); dispatch runs entirely on the portable
oracle until a Fable agent fills `asm_core.montMul` and flips the flag, at which
point the asm-vs-portable differential harness lights up. See `SPEC.md`.

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

Scaffold: 15 pass / 2 skip (Debug and ReleaseFast). The skips are the gated
asm-vs-portable differential (lights up with the core) and the opt-in bench. The
suite includes the byte-exact modmul+modexp KATs at 256/512/2048/4096 bits, the
BrokenMont positive control (a dropped conditional-subtract, flagged RED), the
Karatsuba==schoolbook mutual anchor, and the CT-boundary checks. Portable
baseline this host (ReleaseFast): modmul 2048 ≈ 4.4 µs, modexp 2048 ≈ 5.46 ms;
OpenSSL `rsa2048` CRT sign ≈ 624 µs for reference (`SPEC.md` explains why the
comparison is not apples-to-apples, and what the asm core targets).

Provenance: clean-room from public algorithm descriptions (Montgomery CIOS; the
OpenSSL `x86_64-mont5` `MULX/ADCX/ADOX` technique studied as a design reference;
`std.crypto.ff` API shape). KAT vectors from an independent CPython-bignum
re-derivation. See the `NOTICE` entry.
