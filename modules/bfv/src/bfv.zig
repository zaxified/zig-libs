// SPDX-License-Identifier: MIT

//! bfv — the BFV leveled homomorphic-encryption scheme over the (real,
//! ungated) RNS ring `R_q = Z_q[X]/(X^N+1)` this module ships in Part 1.
//!
//! Scheme (Fan-Vercauteren 2012, "Somewhat Practical Fully Homomorphic
//! Encryption", IACR ePrint 2012/144; parameter/RNS shape follows Microsoft
//! SEAL's BFV): a secret key `s` (small), a public key `(p0,p1)=(-(a·s+e), a)`,
//! ciphertexts that decrypt via `⌊t/q·(c0+c1·s)⌉ mod t`. Plaintext `m∈R_t` is
//! scaled by `Δ=⌊q/t⌋` on encryption. HomAdd is component-wise; HomMul tensors
//! two 2-element ciphertexts into a 3-element one, rescales by `t/q`, and
//! **relinearises** back to 2 elements with an evaluation (relin) key.
//!
//! ## Status — Parts 1–3 are REAL (the full leveled scheme):
//!   - **REAL (Part 1):** the `SecretKey`/`PublicKey`/`RelinKey`/`Ciphertext`
//!     types, `Ciphertext.add`/`sub` (pure ring ops, not noise-sensitive),
//!     and `numComponents`. (Byte codecs for these types are a deferred
//!     backlog item — see `SPEC.md`.)
//!   - **REAL (Part 2, Opus — `scheme_core_implemented`):** `keyGen`,
//!     `encrypt`, `decrypt` — textbook RLWE; the `Δ`-scale decrypt is anchored
//!     by a deterministic noiseless-ciphertext KAT + the enc/dec round-trip and
//!     homomorphic-add end-to-end tests.
//!   - **REAL (Part 3, Fable — `fable_core_implemented`):** `mul` (exact
//!     integer tensor + `⌊t/q·…⌉` rescale), `genRelinKey`/`relinearize`
//!     (base-`w` gadget key-switch for `s²`), `noiseBudget` — the
//!     noise-management core. Anchored by the mul+relin and multiply-DEPTH
//!     end-to-end tests on `params.test_mul`, whose worst-case noise ledger
//!     (params.zig) makes depth-2 correctness a guarantee, not a
//!     probabilistic pass.
//!
//! ## Arithmetic (what the multiply actually runs on)
//! Three exact implementations of the same function, all bit-identical (the
//! differential test asserts it), with a comptime dispatch in `mul`:
//!
//!   - `mulExactRef` — the ORIGINAL `O(N²)` schoolbook tensor over an exact
//!     integer, plus the `⌊t/q·…⌉` rescale by big-integer division. **The
//!     oracle.** Still the fastest path at tiny degree and small modulus.
//!   - `mulRnsNtt` — the tensor in an **auxiliary RNS basis** sized (`num_aux`)
//!     so the centered CRT lift is EXACT: `O(num_aux·N log N)` instead of
//!     `O(N²)`. Still materialises the integer for the rescale.
//!   - `mulBehz` — **BEHZ/HPS**: the tensor in residues over the main basis,
//!     an auxiliary sub-basis and one redundant modulus `m̃`, and the
//!     `⌊t/q·…⌉` rescale done ENTIRELY in residues — an exact RNS division
//!     chain plus a Shenoy–Kumaresan base extension. The exact integer is
//!     never materialised and there is no big-integer division at all. This is
//!     what makes security-grade parameters reachable, and `mul` dispatches to
//!     it whenever `TensorI` outgrows a native 128-bit integer.
//!
//! Word arithmetic is division-free — Shoup for the NTT twiddles, Barrett
//! elsewhere (see `modarith`).
//!
//! Nothing in the module is pinned to `u128` any more: `QU` (the `[0,q)` /
//! CRT-accumulator type) and `TensorI` are both derived from the parameter set,
//! so `params.sec_n8192_logq218` (`N = 8192`, `log q = 218`) builds and runs —
//! see the end-to-end test in `kat_test.zig`. Still deferred: bootstrapping,
//! CKKS, Galois automorphisms, CRT-slot batch encoding.
//!
//! ## Randomness — a security contract, not a portability tag
//!
//! `keyGen`, `encrypt` and `genRelinKey` — the three production entry points
//! that consume entropy — take `io: std.Io` and draw through
//! `entropy.SecureSource`, the fail-closed `std.Random` adapter over
//! `std.Io.randomSecure` (`modules/entropy`). That is deliberately NOT
//! `std.Random.IoSource`, which binds `std.Io.random` — **contractually a
//! CSPRNG** (`std/Io.zig`: "Obtains entropy from a cryptographically secure
//! pseudo-random number generator") but one whose own doc comment documents a
//! silent fallback to a weaker seed if the CSPRNG source fails; the default
//! `Io.Threaded` falls back to a pid+clock+ASLR seed when `getrandom(2)`
//! fails, e.g. under a seccomp policy that blocks it. A bare `std.Random`
//! parameter would still be worse — it would
//! accept `DefaultPrng.init(0)` at a call site that looks identical to a
//! correct one — and either failure mode here is not a weakening but a
//! break: `encrypt`'s `u,e0,e1` are the whole of BFV's IND-CPA claim, so a
//! predictable stream lets anyone compute `c0 − p0·u − e0 = Δ·m` and read the
//! plaintext **without the secret key**; `keyGen`'s `s` becomes a function of
//! the seed; and `genRelinKey` publishes an encryption of `s²` to the
//! evaluator under masks the evaluator can reproduce. `entropy.SecureSource`
//! aborts the process rather than hand back a key drawn from a degraded
//! source — see its doc comment for why that is the right trade at a
//! `void`-returning `std.Random.fillFn`.
//!
//! The `…ForTest` twins keep a `std.Random` parameter, because the KATs in
//! `kat_test.zig` (including the scripted-word test that pins WHICH draws
//! `keyGen` makes, in order) and the seeded end-to-end tests must stay
//! reproducible. Taking `std.Io` rather than reading OS entropy directly keeps
//! the module `platform = .any` — the same shape `bbs`/`ibe`/`tlock` use.
//! Failing closed via `std.Io.randomSecure` was an open, tracked decision
//! (B7); it is now closed (`CONVENTIONS.md` §2.2), and this module takes it.

const std = @import("std");
const builtin = @import("builtin");
const entropy = @import("entropy");
const params = @import("params.zig");
const ring = @import("ring.zig");
const encode = @import("encode.zig");
const gate = @import("gate.zig");
const ma = @import("modarith.zig");
const rns = @import("rns.zig");

/// `Bfv(P)` — a BFV instance for the compile-time-fixed parameter set `P`.
pub fn Bfv(comptime P: params.Params) type {
    const N = P.n;
    const L = P.primes.len;
    // Materialise the prime chain as a comptime array for the ring ops.
    const primes: [L]u64 = blk: {
        var a: [L]u64 = undefined;
        for (0..L) |i| a[i] = P.primes[i];
        break :blk a;
    };

    return struct {
        const Self = @This();
        pub const parameters = P;
        pub const degree = N;
        pub const num_primes = L;
        pub const Ring = ring.RnsPoly(N, L);
        pub const Engine = ring.RnsPoly(N, L).Engine;
        pub const Plaintext = encode.Plaintext(N);

        // ── integer widths, all derived from the parameters ──────────────────
        //
        // `q_product` as an arbitrary-precision comptime integer, so the bound
        // arithmetic below cannot silently wrap a fixed-width accumulator.
        const q_int: comptime_int = blk: {
            var m: comptime_int = 1;
            for (primes) |p| m *= p;
            break :blk m;
        };
        fn bitsOf(v: comptime_int) u16 {
            var x = v;
            var b: u16 = 0;
            while (x > 0) : (b += 1) x >>= 1;
            return b;
        }
        /// `⌈log2(q+1)⌉` — `q < 2^q_bits`.
        pub const q_bits: u16 = bitsOf(q_int);

        /// Unsigned type holding a canonical `[0,q)` value AND the CRT
        /// accumulator, which transiently reaches `2q` (one conditional
        /// subtract per term) — hence `q_bits + 1`.
        ///
        /// This used to be a hard `u128`, and that — not the deleted `i256`
        /// tensor guard — was the last structural block on security-grade
        /// parameters (`log q ≳ 218`). It is now sized from `P`. The `@max(128,
        /// …)` floor keeps every parameter set that fitted before on exactly
        /// the same type, so their arithmetic is bit-identical to what it was.
        pub const QU = std.meta.Int(.unsigned, @max(128, q_bits + 1));
        /// Unsigned type for the round-half-up rescale numerator `2·t·v + q`
        /// (`v < q`), used by `decrypt` / `noiseBudget`. The tight requirement
        /// is `2t(q−1) + q < 2^bits`, i.e. `q_bits + t_bits + 2` in the worst
        /// case (when both `t` and `q` sit just under their bit boundaries);
        /// for every set shipped here `+1` would also fit, so a mutant that
        /// narrows this by one bit survives — by luck of the parameters, not by
        /// equivalence.
        const QRescale = std.meta.Int(.unsigned, @max(128, q_bits + bitsOf(P.t) + 2));

        /// Full ciphertext modulus `q = ∏ q_i` as an integer. Production RNS
        /// never materialises it in the multiply hot path (see `mulBehz`), but
        /// `decrypt`/`noiseBudget`/setup still do.
        pub const q_product: QU = q_int;
        /// The BFV scaling factor `Δ = ⌊q/t⌋` (plaintext lives in the high bits).
        pub const delta: QU = q_product / P.t;

        /// Relinearisation gadget base `w = 2^relin_base_log2` (Part 3).
        /// Parameter-controlled: at `log q ≈ 218` a `w = 2^8` gadget would need
        /// 28 rows, i.e. a 56-polynomial relin key, so security-grade sets pick
        /// a wide base (the key-switch noise `digits·N·(w−1)` is still far under
        /// `Δ/2` there — see the ledger on `params.sec_n8192_logq218`).
        pub const relin_base_log2: u7 = P.relin_base_log2;
        pub const relin_base: u64 = @as(u64, 1) << relin_base_log2;
        /// Number of base-`w` digits covering `q`: `w^relin_digits ≥ q` and
        /// `w^(relin_digits−1) < q` (so every `w^i` used is a `[0,q)` scalar).
        pub const relin_digits: usize = blk: {
            var k: usize = 0;
            var m: comptime_int = q_int;
            while (m > 0) : (k += 1) m >>= relin_base_log2;
            break :blk k;
        };

        comptime {
            // Neither the tensor's integer width nor the ciphertext modulus is
            // pinned any more (`TensorI`, `QU` — both derived from `P`), so the
            // old "2·q_bits + n_bits + t_bits + 2 ≤ 255" and "log q ≤ 127"
            // guards are both gone. What the arithmetic below does still
            // require:
            //   * `t < q` — Δ = ⌊q/t⌋ ≥ 1, and the `mulBehz` quotient bound
            //     `|⌊t·T/q⌋| < ∏p / 2` is derived from it (see `div_bound`).
            //   * `w < 2^63` — the gadget digit is a `u64`.
            if (P.t >= q_int) @compileError("bfv: plaintext modulus t must be < q");
            if (relin_base_log2 >= 63) @compileError("bfv: relin_base_log2 must be < 63");
        }

        // ── auxiliary RNS basis (see `mulRnsNtt` / `mulBehz`) ────────────────
        /// Worst-case magnitude of ANY tensor component coefficient. Centered
        /// inputs satisfy `|x| ≤ (q−1)/2`; a negacyclic convolution coefficient
        /// sums `N` such products, and the middle component `t1` is a sum of
        /// TWO convolutions — hence the factor 2.
        const tensor_bound: comptime_int = blk: {
            const half: comptime_int = (q_int + 1) / 2;
            const n_int: comptime_int = N;
            break :blk 2 * n_int * half * half;
        };
        /// Every auxiliary prime is found by scanning DOWN from `2^62`, so each
        /// contributes at least this many bits to the product.
        const aux_min_bits: comptime_int = 61;
        /// How many auxiliary primes make `∏p_j > 2·tensor_bound`, which is
        /// exactly the condition for the centered CRT lift of the tensor to be
        /// unambiguous (and therefore for the fast path to be EXACT, not
        /// approximate).
        pub const num_aux: usize = blk: {
            var need: comptime_int = 2 * tensor_bound + 1;
            var b: comptime_int = 0;
            while (need > 0) : (b += 1) need >>= 1;
            break :blk @intCast((b + aux_min_bits - 1) / aux_min_bits);
        };
        /// Accumulator type for the auxiliary-basis CRT. Each aux prime is
        /// `< 2^62`, so `∏p_j < 2^(62·num_aux)`; the accumulator is kept below
        /// `∏p_j` by a conditional subtract after every term, so the widest
        /// value it ever holds is `< 2^(62·num_aux + 1) ≤ 2^(64·num_aux)`.
        /// Sizing it at exactly `64·num_aux` (rather than one limb wider) keeps
        /// the common `num_aux = 2` case in a NATIVE `u128`.
        const AuxU = std.meta.Int(.unsigned, 64 * num_aux);

        // ── BEHZ rescale-in-RNS: bounds and basis sizing ─────────────────────
        //
        // `mulBehz` never materialises `T` and never divides a big integer. It
        // computes `D = ⌊t·T/q⌋` by an exact RNS division chain (one main prime
        // at a time) and then base-extends `D` back into the main basis. Two
        // bounds make that exact; both are checked comptime below.
        //
        // (B1) The quotient bound. `|T| ≤ tensor_bound`, so
        //          |t·T/q| ≤ t·tensor_bound/q =: x
        //      and `D = ⌊t·T/q⌋ ∈ [−x−1, x]`, hence `|D| ≤ x + 1`.
        //      `div_shift` below is `trunc(x) + 2 > (x−1) + 2 = x + 1 ≥ |D|`,
        //      so the SHIFTED quotient `z := D + div_shift` satisfies
        //          0 ≤ z ≤ 2·div_shift .
        //      Working with `z` rather than `D` is what lets the base extension
        //      assume a non-negative value in `[0, ∏p)` — see (B2).
        //
        //      MUTATION NOTE. `div_shift` has ~2× slack and halving it is
        //      undetectable, for a reason worth writing down: the correction in
        //      step 3 recovers `α − c` where `c = ⌊z/∏p⌋`, so it reconstructs
        //      the TRUE signed `z`, not `z mod ∏p`, for every `z` in
        //      `(−(m̃−num_rs)·∏p, ∏p)`. The shift is therefore only needed to
        //      keep `z` below `∏p`, not to keep it non-negative — but it is
        //      kept, and (B2) provisioned to the textbook `z ∈ [0,∏p)` bound,
        //      because that is the invariant the code states. What is NOT slack
        //      is (B2) itself: dropping one auxiliary prime is RED.
        const div_shift: comptime_int = (@as(comptime_int, P.t) * tensor_bound) / q_int + 2;

        /// Number of auxiliary primes `mulBehz` actually uses — a PREFIX of
        /// `aux_primes`. It needs only
        ///
        ///   (B2)  ∏_{j<num_rs} p_j  >  2·div_shift ,
        ///
        /// so that `z ∈ [0, 2·div_shift] ⊂ [0, ∏p)` and the Shenoy–Kumaresan
        /// base extension recovers it exactly. That is weaker than the
        /// exact-lift basis's `∏p_j > 2·tensor_bound` by a factor ≈ `q/t`, so
        /// `num_rs ≤ num_aux` always (asserted comptime) and the rescale pays
        /// for far fewer primes than `mulRnsNtt`'s lift would.
        pub const num_rs: usize = blk: {
            var need: comptime_int = 2 * div_shift + 1;
            var b: comptime_int = 0;
            while (need > 0) : (b += 1) need >>= 1;
            const k: usize = @intCast((b + aux_min_bits - 1) / aux_min_bits);
            break :blk @max(1, k);
        };
        /// Moduli `mulBehz` runs the tensor over, on top of the main chain:
        /// `p_0…p_{num_rs−1}` plus the redundant `m̃` (`sk_prime`).
        const num_behz: usize = num_rs + 1;

        comptime {
            // (B2) sizing: every aux prime is ≥ 2^aux_min_bits by construction
            // of the descending scan, so ∏_{j<num_rs} p_j ≥ 2^(61·num_rs), and
            // `num_rs` was chosen with 61·num_rs ≥ bits(2·div_shift + 1), i.e.
            // 2^(61·num_rs) > 2·div_shift. Nothing to check at runtime.
            if (num_rs > num_aux)
                @compileError("bfv: BEHZ sub-basis larger than the exact-lift basis (t ≥ q?)");
            // The base extension recovers `α = ⌊Σ_j ω_j/p_j⌋ ∈ [0, num_rs)` as
            // a residue mod `m̃`; that is only injective while `num_rs < m̃`.
            // `m̃` is ≥ 2^61 and `num_rs` is a handful, so this is slack by ~60
            // bits — but it is the load-bearing inequality, so it is written
            // down rather than assumed.
            if (num_rs >= (1 << aux_min_bits))
                @compileError("bfv: too many auxiliary primes for the redundant modulus");
        }

        /// Exact width the `⌊t/q·T⌉` rescale numerator `|2·t·T + q|` needs,
        /// plus a sign bit. The tensor used to be hardcoded to `i256` — the
        /// widest thing the old comptime guard would admit — which made every
        /// parameter set pay 256-bit division whether it needed it or not.
        /// `test_mul` actually needs 85 bits, so it now rescales in `i128`.
        const rescale_bits: u16 = blk: {
            var v: comptime_int = 2 * @as(comptime_int, P.t) * tensor_bound + q_int;
            var b: u16 = 1; // sign bit
            while (v > 0) : (b += 1) v >>= 1;
            break :blk b;
        };
        /// Signed integer type the exact tensor and its rescale run in. Sized
        /// from the parameters instead of pinned at `i256`.
        pub const TensorI = std.meta.Int(.signed, @max(65, rescale_bits));

        /// The `L` per-prime NTT engines + the prime chain, built once.
        engines: [L]Engine,
        primes: [L]u64,
        /// Precomputed CRT constants for the MAIN basis. `reconstruct` in
        /// `rns.zig` recomputes `∏q`, each `∏_{k≠i} q_k` and a full
        /// `invMod` (a 62-squaring `powMod`) on EVERY call — and the scheme
        /// calls it once per coefficient, i.e. `N` times per decrypt and `4N`
        /// times per multiply. These hoist all of that to `init`.
        crt_mi: [L]QU, // ∏_{k≠i} q_k
        crt_inv: [L]u64, // (crt_mi[i] mod q_i)^{-1} mod q_i
        /// Shoup constant for `Δ mod q_i` (fixed multiplier of `scaledPlaintext`).
        delta_shoup: [L]ma.Shoup,

        /// Auxiliary basis: NTT engines over primes large enough that the
        /// EXACT integer tensor product is recoverable by CRT from its
        /// residues. This is what lets `mul` run the tensor in `O(N log N)`
        /// per prime instead of `O(N²)` over `i256`.
        aux_engines: [num_aux]Engine,
        aux_primes: [num_aux]u64,
        aux_mi: [num_aux]AuxU, // ∏_{k≠j} p_k
        aux_inv: [num_aux]u64, // (aux_mi[j] mod p_j)^{-1} mod p_j
        aux_modulus: AuxU, // ∏ p_j
        /// `q mod p_j` — folds the "centered" correction into the residue
        /// reduction without ever materialising a signed wide integer.
        q_mod_aux: [num_aux]u64,

        // ── BEHZ rescale-in-RNS constants (all hoisted to `init`) ────────────
        /// `m̃`, the redundant modulus that makes the auxiliary→main base
        /// extension EXACT rather than "exact up to a bounded α·∏p". It is one
        /// more NTT-friendly prime (so the tensor can be computed over it too)
        /// taken from the same descending scan, and it is NOT part of `∏p`.
        sk_prime: u64,
        sk_engine: Engine,
        q_mod_sk: u64,
        /// `t mod g` for every modulus `g` the rescale chain runs over.
        t_mod_q: [L]u64,
        t_mod_rs: [num_rs]u64,
        t_mod_sk: u64,
        /// `q_i^{-1} mod g` for each main prime `q_i` divided out by the chain
        /// and each modulus `g` that survives that step.
        qinv_q: [L][L]u64, // only k > i is ever read
        qinv_rs: [L][num_rs]u64,
        qinv_sk: [L]u64,
        /// Shenoy–Kumaresan base-extension constants for `P = ∏_{j<num_rs} p_j`.
        rs_hat_inv: [num_rs]u64, // (P/p_j)^{-1} mod p_j
        rs_hat_q: [num_rs][L]u64, // (P/p_j) mod q_i
        rs_hat_sk: [num_rs]u64, // (P/p_j) mod m̃
        rs_mod_q: [L]u64, // P mod q_i
        rs_inv_sk: u64, // P^{-1} mod m̃
        /// `div_shift mod g` — the constant that keeps the base-extended
        /// quotient non-negative (bound (B1)).
        shift_q: [L]u64,
        shift_rs: [num_rs]u64,
        shift_sk: u64,

        pub const SecretKey = struct {
            s: Ring,

            /// Securely wipe the secret key. `SecretKey` is a single
            /// fixed-size `Ring` (no heap), so zeroing the struct's bytes
            /// erases the ternary secret polynomial `s`. Call when the key
            /// is no longer needed; the struct is left zeroed and must not
            /// be reused. Idempotent — safe to call more than once.
            pub fn deinit(self: *SecretKey) void {
                std.crypto.secureZero(u8, std.mem.asBytes(self));
            }
        };
        pub const PublicKey = struct { p0: Ring, p1: Ring };
        pub const KeyPair = struct { sk: SecretKey, pk: PublicKey };

        /// Relinearisation / evaluation key: a base-`w` gadget key-switching
        /// key for `s²` (layout finalised in Part 3, as Part 1 announced).
        /// Row `i` is a pseudo-encryption of `w^i·s²` under `s`:
        /// `b[i] = −(a[i]·s + e_i) + w^i·s²`, so `b[i] + a[i]·s = w^i·s² − e_i`.
        pub const RelinKey = struct {
            b: [relin_digits]Ring,
            a: [relin_digits]Ring,
        };

        /// A BFV ciphertext: 2 components when fresh or relinearised, 3 after
        /// a multiply. `len ∈ {2,3}`.
        pub const Ciphertext = struct {
            components: [3]Ring,
            len: usize,

            pub fn numComponents(self: *const Ciphertext) usize {
                return self.len;
            }
        };

        /// Build the instance: validates `P`, builds the `L` main NTT engines,
        /// hoists the main-basis CRT constants, and searches for + builds the
        /// `num_aux` auxiliary NTT engines the fast tensor needs.
        pub fn init() !Self {
            try P.validate();
            var local = primes;
            const engines = try ring.makeEngines(N, L, &local);

            // Main-basis CRT constants (hoisted out of `rns.Basis.reconstruct`).
            var crt_mi: [L]QU = undefined;
            var crt_inv: [L]u64 = undefined;
            for (0..L) |i| {
                const mi = q_product / primes[i];
                crt_mi[i] = mi;
                crt_inv[i] = try ma.invMod(@intCast(mi % primes[i]), primes[i]);
            }
            var delta_shoup: [L]ma.Shoup = undefined;
            for (0..L) |i| delta_shoup[i] = ma.Shoup.init(@intCast(delta % primes[i]), primes[i]);

            // Auxiliary basis: the largest NTT-friendly primes below 2^62,
            // scanning down. Distinct by construction (strictly decreasing).
            // One EXTRA prime past `num_aux` is taken as the redundant modulus
            // `m̃` the BEHZ base extension needs; it is deliberately outside
            // `∏p` (both for the aux CRT and for the `num_rs` prefix).
            var aux_primes: [num_aux]u64 = undefined;
            var sk_prime: u64 = 0;
            {
                const two_n: u64 = 2 * @as(u64, N);
                var cand: u64 = (@as(u64, 1) << ma.max_prime_bits) - 1;
                cand -= (cand - 1) % two_n; // largest v < 2^62 with v ≡ 1 mod 2N
                var found: usize = 0;
                while (found < num_aux + 1) : (cand -= two_n) {
                    if (cand <= (@as(u64, 1) << @intCast(aux_min_bits))) return error.NoAuxiliaryPrimes;
                    if (!ma.isPrime(cand)) continue;
                    // The auxiliary primes must be coprime to the main chain;
                    // they are ≥ 2^61 and distinct from each other, but a
                    // parameter set MAY legitimately use a 61/62-bit main
                    // prime, so skip any collision rather than assume.
                    var clash = false;
                    for (primes) |qp| {
                        if (qp == cand) clash = true;
                    }
                    if (clash) continue;
                    if (found < num_aux) aux_primes[found] = cand else sk_prime = cand;
                    found += 1;
                }
            }
            var aux_engines: [num_aux]Engine = undefined;
            for (0..num_aux) |j| aux_engines[j] = try Engine.init(aux_primes[j]);
            const sk_engine = try Engine.init(sk_prime);

            var aux_modulus: AuxU = 1;
            for (aux_primes) |p| aux_modulus *= p;
            var aux_mi: [num_aux]AuxU = undefined;
            var aux_inv: [num_aux]u64 = undefined;
            var q_mod_aux: [num_aux]u64 = undefined;
            for (0..num_aux) |j| {
                const p = aux_primes[j];
                const mi = aux_modulus / p;
                aux_mi[j] = mi;
                aux_inv[j] = try ma.invMod(@intCast(mi % p), p);
                q_mod_aux[j] = @intCast(q_product % p);
            }

            // ── BEHZ constants ───────────────────────────────────────────────
            // `P = ∏_{j<num_rs} p_j` as a comptime-sized unsigned; `num_rs`
            // primes of < 2^62 fit in `64·num_rs` bits with room to spare.
            const RsU = std.meta.Int(.unsigned, 64 * num_rs);
            var rs_modulus: RsU = 1;
            for (0..num_rs) |j| rs_modulus *= aux_primes[j];

            var t_mod_q: [L]u64 = undefined;
            var t_mod_rs: [num_rs]u64 = undefined;
            var shift_q: [L]u64 = undefined;
            var shift_rs: [num_rs]u64 = undefined;
            var rs_mod_q: [L]u64 = undefined;
            var qinv_q: [L][L]u64 = undefined;
            var qinv_rs: [L][num_rs]u64 = undefined;
            var qinv_sk: [L]u64 = undefined;
            var rs_hat_inv: [num_rs]u64 = undefined;
            var rs_hat_q: [num_rs][L]u64 = undefined;
            var rs_hat_sk: [num_rs]u64 = undefined;

            // `div_shift` is a comptime_int that can exceed `u64`; reduce it
            // modularly at comptime, once per modulus, via its bit expansion.
            const ShiftU = std.meta.Int(.unsigned, @max(64, bitsOf(div_shift) + 1));
            const shift_val: ShiftU = div_shift;

            for (0..L) |i| {
                const qi = primes[i];
                t_mod_q[i] = P.t % qi;
                shift_q[i] = @intCast(shift_val % qi);
                rs_mod_q[i] = @intCast(rs_modulus % qi);
                for (0..L) |k| qinv_q[i][k] = if (k == i) 0 else try ma.invMod(qi % primes[k], primes[k]);
                for (0..num_rs) |j| qinv_rs[i][j] = try ma.invMod(qi % aux_primes[j], aux_primes[j]);
                qinv_sk[i] = try ma.invMod(qi % sk_prime, sk_prime);
            }
            for (0..num_rs) |j| {
                const p = aux_primes[j];
                t_mod_rs[j] = P.t % p;
                shift_rs[j] = @intCast(shift_val % p);
                const hat = rs_modulus / p; // P/p_j
                rs_hat_inv[j] = try ma.invMod(@intCast(hat % p), p);
                for (0..L) |i| rs_hat_q[j][i] = @intCast(hat % primes[i]);
                rs_hat_sk[j] = @intCast(hat % sk_prime);
            }

            return .{
                .engines = engines,
                .primes = primes,
                .crt_mi = crt_mi,
                .crt_inv = crt_inv,
                .delta_shoup = delta_shoup,
                .aux_engines = aux_engines,
                .aux_primes = aux_primes,
                .aux_mi = aux_mi,
                .aux_inv = aux_inv,
                .aux_modulus = aux_modulus,
                .q_mod_aux = q_mod_aux,
                .sk_prime = sk_prime,
                .sk_engine = sk_engine,
                .q_mod_sk = @intCast(q_product % sk_prime),
                .t_mod_q = t_mod_q,
                .t_mod_rs = t_mod_rs,
                .t_mod_sk = P.t % sk_prime,
                .qinv_q = qinv_q,
                .qinv_rs = qinv_rs,
                .qinv_sk = qinv_sk,
                .rs_hat_inv = rs_hat_inv,
                .rs_hat_q = rs_hat_q,
                .rs_hat_sk = rs_hat_sk,
                .rs_mod_q = rs_mod_q,
                .rs_inv_sk = try ma.invMod(@intCast(rs_modulus % sk_prime), sk_prime),
                .shift_q = shift_q,
                .shift_rs = shift_rs,
                .shift_sk = @intCast(shift_val % sk_prime),
            };
        }

        /// Exact CRT reconstruction of one coefficient's residues into
        /// `[0, q)`, using the constants hoisted at `init`. Bit-identical to
        /// `rns.Basis.reconstruct` (which stays as the differential oracle),
        /// but with no `invMod` / no `∏q` recomputation per call.
        ///
        /// The accumulator adds one `[0,q)` term at a time with a conditional
        /// subtract, so it never exceeds `2q` — which is why `QU` is sized at
        /// `q_bits + 1` and not `q_bits`.
        pub fn reconstruct(self: *const Self, residues: *const [L]u64) QU {
            var acc: QU = 0;
            for (0..L) |i| {
                const c: u64 = self.engines[i].modulus.mul(residues[i], self.crt_inv[i]);
                // `crt_mi[i]·c ≤ (q/q_i)·(q_i−1) < q`, so each term needs no
                // reduction of its own and `acc + term < 2q ≤ 2^(q_bits+1)`.
                acc += self.crt_mi[i] * @as(QU, c);
                if (acc >= q_product) acc -= q_product;
            }
            return acc;
        }

        /// `x mod q_i` for a wide `[0,q)` value — Barrett Horner over 64-bit
        /// limbs, never a big-integer division. Compiles to the plain `u128`
        /// Barrett reduce for every parameter set whose `q` fits in 128 bits,
        /// so those stay bit-identical AND cost-identical to before.
        inline fn reduceQ(m: *const ma.Modulus, v: QU) u64 {
            return m.reduceWide(QU, v);
        }

        // ── REAL, ungated ops ────────────────────────────────────────────────

        /// Homomorphic addition `Enc(a) ⊕ Enc(b)` — component-wise ring add.
        /// Pure `R_q` arithmetic, not noise-sensitive, so it is REAL in
        /// Part 1 (though it is only observable once `encrypt`/`decrypt` land).
        /// Both inputs must have the same component count.
        pub fn add(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            std.debug.assert(x.len == y.len);
            var out = x.*;
            for (0..x.len) |i| out.components[i].addAssign(&y.components[i], &self.primes);
            return out;
        }

        /// Homomorphic subtraction, component-wise.
        pub fn sub(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            std.debug.assert(x.len == y.len);
            var out = x.*;
            for (0..x.len) |i| out.components[i].subAssign(&y.components[i], &self.primes);
            return out;
        }

        // ── scheme core (Part 2, Opus — textbook RLWE) ───────────────────────
        //
        // Correctness anchor (SPEC.md "Anchors"): decrypt inverts the `Δ`-scale
        // exactly on a hand-constructed noiseless ciphertext (deterministic KAT,
        // independent of keyGen/encrypt); the fresh-encryption noise
        // `E = −e·u + e0 + e1·s` is bounded ≪ `Δ/2`, so the enc/dec round-trip
        // and homomorphic-add end-to-end anchors decrypt back byte-exact for
        // EVERY seed (not a probabilistic property at this depth).

        /// Sample a ternary polynomial (each coefficient uniform in `{−1,0,1}`)
        /// as a coefficient-domain ring element. Used for the secret key, the
        /// encryption randomness `u`, and the small errors `e,e0,e1` — a
        /// consistent small integer per coefficient across all RNS limbs
        /// (`−1 ↦ q_i−1`), which keeps the decrypt-noise a genuine small
        /// integer.
        ///
        /// ## Constant-time shape (what this does and does not buy)
        /// This sampler produces the secret key `s` and the errors `e,e0,e1` —
        /// the module's most sensitive values — so it must not branch on, or
        /// index by, the trit it drew. Two things were needed:
        ///
        ///   - **The draw.** `std.Random.uintLessThan(u8, 3)` is a *rejection*
        ///     loop: its iteration count depends on the value drawn, which
        ///     correlates with the trit. It is replaced by std's own
        ///     documented constant-time variant, `uintLessThanBiased`, over a
        ///     full 64-bit word — the fixed-cost multiply-shift map
        ///     `r = ⌊x·3 / 2^64⌋` (Lemire's reduction with the rejection step
        ///     dropped). The width matters: at `u8` the bias would be `3/256`,
        ///     at `u64` it is not. This is not exactly uniform: the outcomes get
        ///     `⌈2^64/3⌉ , ⌊2^64/3⌋ , ⌊2^64/3⌋` of the `2^64` words, so each
        ///     probability is within `2/(3·2^64) < 2^-63` of `1/3`. Summed over
        ///     every coefficient this module ever samples the statistical
        ///     distance from a true uniform ternary is far below `2^-50` —
        ///     cryptographically irrelevant, and unlike the rejection loop it
        ///     is fixed-cost.
        ///   - **The store.** The `switch (r)` on the secret trit is replaced by
        ///     an arithmetic mask select (`is_neg`/`is_pos` are all-ones or
        ///     all-zero words derived from `@intFromBool`, and the two cases are
        ///     mutually exclusive so `|` merges them).
        ///
        /// **Not** claimed: this is source-level constant time only. The
        /// compiler may rematerialise a branch from a mask, `random`'s own
        /// implementation is the caller's to choose (a rejection-based or
        /// buffered PRNG can reintroduce data-dependent timing upstream of
        /// here), and nothing constrains the microarchitecture. See SPEC.md
        /// "Threats / caveats" for the parts of the module that are still not
        /// constant-time at all.
        fn sampleTernary(self: *const Self, random: std.Random) Ring {
            var out = Ring.zero(.coeff);
            for (0..N) |j| {
                // r ∈ {0,1,2} ↦ −1,0,+1 — fixed cost, no rejection loop.
                const r: u64 = random.uintLessThanBiased(u64, 3);
                const is_neg: u64 = 0 -% @as(u64, @intFromBool(r == 0));
                const is_pos: u64 = 0 -% @as(u64, @intFromBool(r == 2));
                for (0..L) |i| {
                    out.limbs[i][j] = ((self.primes[i] - 1) & is_neg) | (1 & is_pos);
                }
            }
            return out;
        }

        /// Sample a uniform ring element in `R_q` (each limb uniform in
        /// `[0,q_i)` — by CRT this is uniform mod `q`). Used for the public-key
        /// mask `a`.
        fn sampleUniform(self: *const Self, random: std.Random) Ring {
            var out = Ring.zero(.coeff);
            for (0..L) |i| {
                for (0..N) |j| out.limbs[i][j] = random.uintLessThan(u64, self.primes[i]);
            }
            return out;
        }

        /// `Δ·m` as a coefficient-domain ring element. `Δ·m_j < q`, so the
        /// per-limb `(Δ mod q_i)·(m_j mod q_i) mod q_i` equals the residue of
        /// the integer `Δ·m_j` (no wrap).
        fn scaledPlaintext(self: *const Self, pt: *const Plaintext) Ring {
            var out = Ring.zero(.coeff);
            for (0..L) |i| {
                const qi = self.primes[i];
                // `Δ mod q_i` is fixed for the whole limb ⇒ Shoup; the
                // coefficient reduction is Barrett. Neither divides.
                const ds = self.delta_shoup[i];
                const m = &self.engines[i].modulus;
                for (0..N) |j| out.limbs[i][j] = ds.mul(m.reduce(pt.coeffs[j]), qi);
            }
            return out;
        }

        /// Generate a BFV keypair. `io`'s CSPRNG supplies the secret (ternary)
        /// key `s`, the uniform public-key mask `a`, and the small error `e`.
        /// `pk = (p0, p1) = (−(a·s + e), a)`.
        ///
        /// `io` must be a real `std.Io`: the draw goes through
        /// `entropy.SecureSource`, fail-closed on `std.Io.randomSecure`, which
        /// is why this parameter is not a `std.Random`. All three
        /// values come off one stream, so a seeded PRNG makes `s` a
        /// deterministic function of the seed: whoever guesses it, or reads it
        /// out of the consumer's binary, decrypts every ciphertext ever
        /// produced under that key. See `keyGenForTest` for the reproducible
        /// twin the KATs use.
        pub fn keyGen(self: *const Self, io: std.Io) KeyPair {
            var src: entropy.SecureSource = .{ .io = io };
            return self.keyGenForTest(src.interface());
        }

        /// TEST/KAT ONLY — `keyGen` with caller-chosen draws, so the KATs can
        /// script the exact word sequence `s`, `a` and `e` are sampled from.
        /// A `std.Random` here may be `DefaultPrng.init(0)`, which as a *key*
        /// source is equivalent to publishing the key.
        pub fn keyGenForTest(self: *const Self, random: std.Random) KeyPair {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            const s = self.sampleTernary(random);
            const a = self.sampleUniform(random);
            const e = self.sampleTernary(random);
            var p0 = a.mul(&s, &self.engines); // a·s
            p0.addAssign(&e, &self.primes); // a·s + e
            p0.negate(&self.primes); // −(a·s + e)
            return .{ .sk = .{ .s = s }, .pk = .{ .p0 = p0, .p1 = a } };
        }

        /// Encrypt `pt ∈ R_t`: `c0 = Δ·m + p0·u + e0`, `c1 = p1·u + e1`,
        /// `Δ = ⌊q/t⌋`. `io`'s CSPRNG supplies the ternary `u,e0,e1`.
        ///
        /// `io` must be a real `std.Io`. These three values ARE the encryption:
        /// the ciphertext is a deterministic function of `(pk, m, u, e0, e1)`,
        /// so if the stream is predictable an attacker recomputes `u` and `e0`
        /// and reads `c0 − p0·u − e0 = Δ·m` — recovering the plaintext with no
        /// secret key involved at all. Encryption randomness is the whole of
        /// BFV's IND-CPA claim, which is why this takes `std.Io` and not a
        /// `std.Random` a seeded PRNG could satisfy.
        pub fn encrypt(self: *const Self, pk: *const PublicKey, pt: *const Plaintext, io: std.Io) Ciphertext {
            var src: entropy.SecureSource = .{ .io = io };
            return self.encryptForTest(pk, pt, src.interface());
        }

        /// TEST/KAT ONLY — `encrypt` with caller-chosen draws (deterministic
        /// ciphertexts for the round-trip and noise-ledger tests).
        pub fn encryptForTest(self: *const Self, pk: *const PublicKey, pt: *const Plaintext, random: std.Random) Ciphertext {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            const u = self.sampleTernary(random);
            const e0 = self.sampleTernary(random);
            const e1 = self.sampleTernary(random);
            var c0 = self.scaledPlaintext(pt); // Δ·m
            var p0u = pk.p0.mul(&u, &self.engines);
            c0.addAssign(&p0u, &self.primes); // + p0·u
            c0.addAssign(&e0, &self.primes); // + e0
            var c1 = pk.p1.mul(&u, &self.engines);
            c1.addAssign(&e1, &self.primes); // p1·u + e1
            return .{ .components = .{ c0, c1, Ring.zero(.coeff) }, .len = 2 };
        }

        /// Decrypt: `⌊t/q·(Σ_i c_i·s^i)⌉ mod t`, coefficient-wise. The phase
        /// `Σ_i c_i·s^i = Δ·m + E` is reconstructed exactly per coefficient via
        /// CRT, then rescaled with round-half-up
        /// `⌊(2·t·v + q)/(2q)⌋ mod t`. Handles `len ∈ {2,3}` (a 3-component
        /// ciphertext — post-multiply — needs the `c2·s²` term).
        pub fn decrypt(self: *const Self, sk: *const SecretKey, ct: *const Ciphertext) Plaintext {
            // phase = Σ_i c_i·s^i in R_q (c0 + c1·s [+ c2·s² …]).
            var acc = ct.components[0];
            if (ct.len >= 2) {
                var spow = sk.s; // s^1
                var term = ct.components[1].mul(&spow, &self.engines);
                acc.addAssign(&term, &self.primes);
                var i: usize = 2;
                while (i < ct.len) : (i += 1) {
                    spow = spow.mul(&sk.s, &self.engines); // s^i
                    var t2 = ct.components[i].mul(&spow, &self.engines);
                    acc.addAssign(&t2, &self.primes);
                }
            }
            // ⌊t/q · phase⌉ mod t, coefficient-wise, via exact CRT reconstruction.
            var out = Plaintext.zero(P.t);
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = acc.limbs[i][j];
                const v = self.reconstruct(&res); // in [0, q)
                // round(t·v/q) = ⌊(2·t·v + q) / (2q)⌋ ; then reduce mod t.
                // `QRescale` is exactly wide enough for `2·t·v + q < 2·t·q + q`.
                const qr: QRescale = q_product;
                const rounded = (2 * @as(QRescale, P.t) * @as(QRescale, v) + qr) / (2 * qr);
                out.coeffs[j] = @intCast(rounded % @as(QRescale, P.t));
            }
            return out;
        }

        // ── Fable core (Part 3 — noise management) ───────────────────────────
        //
        // Correctness story (SPEC.md "Part-3 noise budget"): write the exact
        // integer identity `ct(s) = c0 + c1·s = Δ·m + v + q·r` (centered
        // representatives, ‖r‖ ≤ (N+3)/2). Then
        //   ct1(s)·ct2(s) = Δ²m1m2 + Δ(m1v2+m2v1) + v1v2
        //                 + q·[r1(Δm2+v2) + r2(Δm1+v1)] + q²·r1r2 ,
        // and multiplying by t/q (with tΔ = q − r_t, r_t = q mod t) gives
        //   (t/q)·ct1(s)·ct2(s) ≡ Δ·[m1m2]_t + v_mult   (mod q),
        //   v_mult = (m1v2+m2v1) + t·(r1v2+r2v1)  [dominant]
        //          − r_t·(r1m2+r2m1 + m1m2-carries + …) + (t/q)·v1v2 ,
        // i.e. the t/q rescale CANCELS one Δ so the product stays scaled by Δ
        // (not Δ²), and the noise grows ≈ multiplicatively (·t·N·‖r‖), NOT to
        // Δ²-scale garbage. The per-component rounding `⌊t/q·T_i⌉` adds
        // ε0+ε1·s+ε2·s² ≤ (1+N+N²)/2. CRITICALLY the tensor `T_i` must be an
        // EXACT integer product of fixed `[0,q)`-representative polynomials
        // (centered here, to halve the noise constants): rescaling a mod-q
        // ring product instead would drop `t·k_i ≢ 0 (mod q)` per component
        // and decrypt to garbage — which is why `mul` reconstructs exactly
        // instead of staying in RNS. The security-grade fast path (BEHZ/HPS
        // RNS base extension, never materialising the integer) is the
        // deferred increment (SPEC.md).

        /// Exact CRT lift of a coeff-domain ring element: every coefficient
        /// reconstructed to its canonical `[0, q)` representative. Both the
        /// reference tensor (which centers these into `i256`) and the fast
        /// tensor (which reduces them into the auxiliary basis) start here.
        fn rawCoeffs(self: *const Self, r: *const Ring) [N]QU {
            std.debug.assert(r.domain == .coeff);
            var out: [N]QU = undefined;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = r.limbs[i][j];
                out[j] = self.reconstruct(&res);
            }
            return out;
        }

        /// Center `[0,q)` representatives into `(−q/2, q/2]` as `i256`, so the
        /// reference tensor products stay exact.
        fn centerRaw(raw: *const [N]QU) [N]TensorI {
            const half = q_product / 2;
            var out: [N]TensorI = undefined;
            for (0..N) |j| {
                const v = raw[j];
                out[j] = if (v > half)
                    -@as(TensorI, @intCast(q_product - v))
                else
                    @as(TensorI, @intCast(v));
            }
            return out;
        }

        /// Exact centered integer coefficients of a coeff-domain ring element.
        fn centeredCoeffs(self: *const Self, r: *const Ring) [N]TensorI {
            const raw = self.rawCoeffs(r);
            return centerRaw(&raw);
        }

        /// `acc += a·b mod (X^N+1)` over the integers (exact schoolbook
        /// negacyclic convolution; |terms| ≤ N·(q/2)², guarded comptime).
        ///
        /// **This is the oracle**, not the hot path: `mul` runs the tensor
        /// through the auxiliary RNS-NTT basis (`tensorNtt`) and
        /// `mulExactRef` — this `O(N²)` `i256` schoolbook — is what the
        /// differential test asserts it is bit-identical to.
        fn negaMulAcc(a: *const [N]TensorI, b: *const [N]TensorI, acc: *[N]TensorI) void {
            for (0..N) |i| {
                for (0..N) |j| {
                    const p = a[i] * b[j];
                    const k = i + j;
                    if (k < N) acc[k] += p else acc[k - N] -= p; // X^N = −1
                }
            }
        }

        /// Residues mod one auxiliary modulus `g` of the CENTERED integers
        /// whose `[0,q)` representatives are `raw`. Centering is folded in
        /// arithmetically: for `v > q/2` the centered value is `v − q`, so its
        /// residue is `(v mod g) − (q mod g)`. No signed wide integer, and no
        /// wide-by-`u64` division, ever appears.
        fn centeredResidues(eng: *const Engine, q_mod_g: u64, raw: *const [N]QU) [N]u64 {
            const p = eng.q;
            const m = &eng.modulus;
            const half = q_product / 2;
            var out: [N]u64 = undefined;
            for (0..N) |i| {
                const v = raw[i];
                const r = reduceQ(m, v);
                out[i] = if (v > half) ma.subMod(r, q_mod_g, p) else r;
            }
            return out;
        }

        /// The three exact-integer tensor components, reduced mod ONE modulus
        /// `g`: 4 forward NTTs, 3 pointwise components, 3 inverse NTTs. Shared
        /// by `mulRnsNtt` (which then CRT-lifts them) and `mulBehz` (which
        /// never lifts them at all).
        fn tensorModulus(
            eng: *const Engine,
            q_mod_g: u64,
            x0: *const [N]QU,
            x1: *const [N]QU,
            y0: *const [N]QU,
            y1: *const [N]QU,
            o0: *[N]u64,
            o1: *[N]u64,
            o2: *[N]u64,
        ) void {
            const p = eng.q;
            const m = &eng.modulus;
            var a0 = centeredResidues(eng, q_mod_g, x0);
            var a1 = centeredResidues(eng, q_mod_g, x1);
            var b0 = centeredResidues(eng, q_mod_g, y0);
            var b1 = centeredResidues(eng, q_mod_g, y1);
            eng.forward(&a0);
            eng.forward(&a1);
            eng.forward(&b0);
            eng.forward(&b1);
            for (0..N) |i| {
                o0[i] = m.mul(a0[i], b0[i]);
                o1[i] = ma.addMod(m.mul(a0[i], b1[i]), m.mul(a1[i], b0[i]), p);
                o2[i] = m.mul(a1[i], b1[i]);
            }
            eng.inverse(o0);
            eng.inverse(o1);
            eng.inverse(o2);
        }

        /// Centered CRT lift from the auxiliary basis back to an exact `i256`.
        /// Unambiguous because `∏p_j > 2·tensor_bound ≥ 2·|T|` by construction
        /// of `num_aux` — this is what makes the NTT tensor EXACT rather than
        /// an approximation with an error term to bound.
        fn auxCenter(self: *const Self, residues: *const [num_aux]u64) TensorI {
            var acc: AuxU = 0;
            for (0..num_aux) |j| {
                const c: u64 = self.aux_engines[j].modulus.mul(residues[j], self.aux_inv[j]);
                // `aux_mi[j]·c ≤ (∏p/p_j)·(p_j−1) < ∏p`, so one conditional
                // subtract per term keeps `acc < ∏p`.
                acc += self.aux_mi[j] * @as(AuxU, c);
                if (acc >= self.aux_modulus) acc -= self.aux_modulus;
            }
            const half = self.aux_modulus / 2; // ∏p is odd ⇒ (∏p−1)/2
            return if (acc > half)
                -@as(TensorI, @intCast(self.aux_modulus - acc))
            else
                @as(TensorI, @intCast(acc));
        }

        /// The RNS-NTT exact tensor — the replacement for the `O(N²)` `i256`
        /// schoolbook. For each auxiliary prime: forward-NTT the four input
        /// polynomials, form the three tensor components by POINTWISE products
        /// in the NTT domain, inverse-NTT them, and keep the residues. A
        /// centered CRT lift over the auxiliary basis then recovers the exact
        /// integer tensor.
        ///
        /// Cost: `7` transforms + `4N` pointwise products per auxiliary prime,
        /// i.e. `O(num_aux · N log N)` word operations, against the reference's
        /// `O(N²)` `i256` (4-limb) multiplies.
        pub fn tensorNtt(
            self: *const Self,
            x0: *const [N]QU,
            x1: *const [N]QU,
            y0: *const [N]QU,
            y1: *const [N]QU,
            out: *[3][N]TensorI,
        ) void {
            var res: [3][num_aux][N]u64 = undefined;
            for (0..num_aux) |j| {
                tensorModulus(
                    &self.aux_engines[j],
                    self.q_mod_aux[j],
                    x0,
                    x1,
                    y0,
                    y1,
                    &res[0][j],
                    &res[1][j],
                    &res[2][j],
                );
            }
            for (0..3) |c| {
                for (0..N) |i| {
                    var r: [num_aux]u64 = undefined;
                    for (0..num_aux) |j| r[j] = res[c][j][i];
                    out[c][i] = self.auxCenter(&r);
                }
            }
        }

        /// `⌊t/q · T⌉ mod q` per coefficient (round half up via floor
        /// division, exact for negative T), decomposed back into RNS limbs.
        ///
        /// MEASURED NOTE (bench.zig): the two `i256` big-integer divisions here
        /// look like the obvious next target once the tensor stops being
        /// `O(N²)`, and they are NOT. Replacing the `@mod` with a division-free
        /// 4-limb Horner reduction (`2^64 mod q_i` + Barrett, exploiting
        /// `q_i | q`) was implemented and measured: it made the rescale go from
        /// ~31 ns to ~250 ns per coefficient and `mul` at N=16 from 8.8 µs to
        /// 19.4 µs — an 8x REGRESSION. LLVM lowers these `i256` divisions well
        /// (the divisor is a loop constant), and the Horner chain is fully
        /// serialised. Reverted; do not "optimise" this again without a bench.
        pub fn rescaleTensor(self: *const Self, tc: *const [N]TensorI) Ring {
            var out = Ring.zero(.coeff);
            const qi: TensorI = @intCast(q_product);
            const ti: TensorI = @intCast(P.t);
            for (0..N) |j| {
                const rounded = @divFloor(2 * ti * tc[j] + qi, 2 * qi);
                const v: QU = @intCast(@mod(rounded, qi)); // canonical [0, q)
                for (0..L) |i| out.limbs[i][j] = reduceQ(&self.engines[i].modulus, v);
            }
            return out;
        }

        /// `scalar·r` for a `[0,q)` scalar, per-limb (legal in either domain).
        /// The per-limb scalar is fixed for the whole limb ⇒ Shoup.
        fn scalarMul(self: *const Self, r: *const Ring, scalar: QU) Ring {
            var out = r.*;
            for (0..L) |i| {
                const qi = self.primes[i];
                const s = ma.Shoup.init(reduceQ(&self.engines[i].modulus, scalar), qi);
                for (&out.limbs[i]) |*x| x.* = s.mul(x.*, qi);
            }
            return out;
        }

        /// Generate the relinearisation key: a base-`w` gadget key-switching
        /// key for `s²`. Row `i` pseudo-encrypts `w^i·s²` under `s` with a
        /// fresh ternary error `e_i`: `(b_i, a_i) = (−(a_i·s + e_i) + w^i·s²,
        /// a_i)`. `io`'s CSPRNG supplies the uniform `a_i` and ternary `e_i`.
        ///
        /// `io` must be a real `std.Io`. The relinearisation key is *published*
        /// to whoever evaluates the circuit, and every row is an encryption of
        /// a gadget multiple of `s²` under masks drawn here: with a predictable
        /// stream the evaluator subtracts the known `a_i·s + e_i` and reads
        /// `w^i·s²` off directly, i.e. the key hands the secret key to the
        /// party it was meant to hide it from.
        pub fn genRelinKey(self: *const Self, sk: *const SecretKey, io: std.Io) RelinKey {
            var src: entropy.SecureSource = .{ .io = io };
            return self.genRelinKeyForTest(sk, src.interface());
        }

        /// TEST/KAT ONLY — `genRelinKey` with caller-chosen draws.
        pub fn genRelinKeyForTest(self: *const Self, sk: *const SecretKey, random: std.Random) RelinKey {
            // TEST-ONLY, ENFORCED. The `ForTest` name warns; this makes it true.
            // Taking a caller-supplied `std.Random` is exactly how a seeded PRNG
            // becomes key material, so production must not be able to reach this
            // by typing a longer identifier. Tests compile with `is_test`, so the
            // KATs that need a scripted draw sequence are unaffected.
            comptime if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
            const s2 = sk.s.mul(&sk.s, &self.engines);
            var rlk: RelinKey = undefined;
            var w_pow: QU = 1; // w^i < q for all rows used (see relin_digits)
            for (0..relin_digits) |i| {
                const a_i = self.sampleUniform(random);
                const e_i = self.sampleTernary(random);
                var b_i = self.scalarMul(&s2, w_pow); // w^i·s²
                var mask = a_i.mul(&sk.s, &self.engines); // a_i·s
                mask.addAssign(&e_i, &self.primes); // + e_i
                b_i.subAssign(&mask, &self.primes); // w^i·s² − (a_i·s + e_i)
                rlk.b[i] = b_i;
                rlk.a[i] = a_i;
                const WPow = std.meta.Int(.unsigned, @as(u16, @bitSizeOf(QU)) + relin_base_log2);
                w_pow = @intCast((@as(WPow, w_pow) << relin_base_log2) % @as(WPow, q_product));
            }
            return rlk;
        }

        /// Homomorphic multiply → a 3-component ciphertext (degree 2 in `s`).
        /// Tensor `(c0,c1)⊗(d0,d1) = (c0d0, c0d1+c1d0, c1d1)` computed EXACTLY
        /// over the integers (centered representatives — see the correctness
        /// note above for why a mod-q ring tensor would be silently wrong),
        /// then the `⌊t/q·…⌉` rescale per component, which keeps the plaintext
        /// scaled by `Δ` (not `Δ²`). Decrypts with `(1, s, s²)`;
        /// `relinearize` reduces it back to 2 components.
        /// Ring degree at or above which `mul` takes the RNS-NTT tensor. Below
        /// it the `O(N²)` schoolbook is genuinely faster: at small `N` the
        /// per-multiply fixed costs (CRT lift + the `⌊t/q·⌉` rescale) dominate
        /// both paths, and `7·num_aux` transforms cost more than `N²` narrow
        /// multiplies. MEASURED (bench.zig, ReleaseFast, this host — schoolbook
        /// vs RNS-NTT, so >1 means the NTT path wins):
        ///
        /// This constant now only decides the SMALL-modulus corner
        /// (`TensorI ≤ behz_min_tensor_bits`); above that `mul` takes BEHZ at
        /// every degree. Re-measured after the dead-code guard went into
        /// `bench.zig`, at `q ≈ 2^36` (the only modulus size still in this
        /// regime), schoolbook µs vs `mulRnsNtt` µs:
        ///
        /// | N   | schoolbook | RNS-NTT | ratio |
        /// |-----|------------|---------|-------|
        /// |  16 |    4.4     |   4.96  | 0.89  |
        /// |  32 |   12.9     |  10.4   | 1.24  |
        /// |  64 |   43.0     |  21.4   | 2.01  |
        /// | 256 |  507.5     | 174.8   | 2.90  |
        /// | 512 | 1985.5     | 357.3   | 5.56  |
        ///
        /// `32` is still the first degree where the transform pays for itself.
        /// The shipped sets land deliberately: `test_tiny`/`test_mul` (N=8/16,
        /// `TensorI` = i65/i86) keep the schoolbook; `bfv_toy` (`TensorI` =
        /// i142) and `sec_n8192_logq218` (i467) take BEHZ.
        pub const ntt_tensor_min_degree: usize = 32;

        /// `TensorI` width above which `mul` takes the BEHZ path. This is the
        /// measured discriminator, and it has a mechanical reason: the exact
        /// rescale's `@divFloor`/`@mod` have a COMPILE-TIME constant divisor
        /// (`q` is a `pub const`), and LLVM turns such a division into a
        /// multiply-by-reciprocal only while the dividend fits a native
        /// 128-bit integer. One limb wider and it becomes a multi-limb library
        /// routine whose cost grows superlinearly — 44 ns → 424 ns → 1868 ns →
        /// 5577 ns per coefficient at `TensorI` = i81 / i142 / i369 / i608.
        /// BEHZ pays `L` extra prime-NTT sets for the main-basis tensor and
        /// stays flat (64 → 111 → 232 → 378 ns), so the two curves cross
        /// exactly where the native division stops.
        ///
        /// MEASURED (`bench.zig`, `-Doptimize=ReleaseFast`, this host; the
        /// whole 3-component result is kept alive — see the note there, an
        /// earlier draft let LLVM dead-code two thirds of every path and
        /// reported the crossover ~2× too high). Ratio = BEHZ over the best
        /// non-BEHZ path; `>1` means BEHZ wins:
        ///
        /// | log2 q | chain  | N        | TensorI | ratio (2 runs)  |
        /// |--------|--------|----------|---------|-----------------|
        /// |   36   | 2×18b  | 16…512   | i81–i90 | 0.54–0.69       |
        /// |   60   | 2×30b  | 16…512   | i130+   | 1.14–2.34       |
        /// |   60   | 2×30b  | 256      | i134    | 0.97 / 1.19  ←  |
        /// |   90   | 3×30b  | 256      | i194    | 1.33            |
        /// |  120   | 4×30b  | 256      | i254    | 1.19 / 1.31     |
        /// |  120   | 2×60b  | 256      | i254    | 1.95            |
        /// |  150   | 5×30b  | 256      | i314    | 1.47 / 1.53     |
        /// |  180   | 3×60b  | 256/16   | i374    | 2.45–2.51 / 4.7–5.1 |
        /// |  240   | 4×60b  | 256      | i494    | 2.80 / 2.89     |
        /// |  300   | 5×60b  | 256/8    | i614    | 3.43 / 7.6–10.7 |
        /// |  360   | 6×60b  | 256      | i734    | 3.42 / 4.02     |
        ///
        /// Every set with `TensorI ≤ 128` prefers the old path, every set above
        /// it prefers BEHZ, at every degree measured. The single genuinely
        /// borderline row is marked `←`: `TensorI = i134` is six bits past the
        /// line and the two runs straddle 1.0, which is exactly what a real
        /// crossover looks like — the cost of getting it wrong there is a few
        /// percent, against 3–10× further out.
        ///
        /// The `log2 q = 36` row is the only one below the line and it is also
        /// the only one where the schoolbook is still in play, which is why the
        /// dispatch below checks this FIRST: at wide moduli BEHZ beats the
        /// schoolbook even at N=8 (10.7× at `log q = 300`).
        pub const behz_min_tensor_bits: u16 = 128;

        /// Homomorphic multiply. Dispatches at COMPTIME between the three
        /// tensor+rescale implementations — all three are exact and, by the
        /// differential test, bit-identical; the choice is purely which is
        /// faster at these parameters.
        pub fn mul(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            if (comptime @bitSizeOf(TensorI) > behz_min_tensor_bits) return self.mulBehz(x, y);
            return if (comptime N >= ntt_tensor_min_degree)
                self.mulRnsNtt(x, y)
            else
                self.mulExactRef(x, y);
        }

        /// Tensor via the auxiliary RNS-NTT basis: `O(num_aux · N log N)`.
        /// Called directly by the differential test at EVERY parameter set, so
        /// it stays covered even where `mul` does not dispatch to it.
        pub fn mulRnsNtt(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            var t: [3][N]TensorI = undefined;
            self.tensorExactLift(x, y, &t);
            return .{ .components = .{
                self.rescaleTensor(&t[0]),
                self.rescaleTensor(&t[1]),
                self.rescaleTensor(&t[2]),
            }, .len = 3 };
        }

        /// The exact integer tensor, materialised — auxiliary-basis NTT plus
        /// the centered CRT lift. Split out of `mulRnsNtt` so `bench.zig` can
        /// feed the OLD rescale a real tensor without timing the transform.
        pub fn tensorExactLift(self: *const Self, x: *const Ciphertext, y: *const Ciphertext, out: *[3][N]TensorI) void {
            std.debug.assert(x.len == 2 and y.len == 2);
            const x0 = self.rawCoeffs(&x.components[0]);
            const x1 = self.rawCoeffs(&x.components[1]);
            const y0 = self.rawCoeffs(&y.components[0]);
            const y1 = self.rawCoeffs(&y.components[1]);
            self.tensorNtt(&x0, &x1, &y0, &y1, out);
        }

        // ── BEHZ: the `⌊t/q·T⌉` rescale done entirely in residues ────────────
        //
        // `rescaleTensor` above needs the exact integer `T`, and therefore a CRT
        // lift into a `2·q_bits`-wide signed type plus two big-integer divisions
        // per coefficient. That is what kept the module on toy moduli. The
        // routine below computes the SAME value with word arithmetic only.
        //
        // Notation: `T` is one exact integer tensor component coefficient,
        // `A₀ = t·T`, `q = ∏_{i<L} q_i`, `P = ∏_{j<num_rs} p_j`, `m̃ = sk_prime`.
        //
        // STEP 1 — the rounding bit. With `D := ⌊t·T/q⌋` (floor, exact for
        //   negative `T` too) and `ρ := [t·T]_q ∈ [0,q)`:
        //       2tT + q = 2qD + 2ρ + q ,
        //   so `⌊(2tT+q)/(2q)⌋ = D + ⌊(2ρ+q)/(2q)⌋ = D + b`, where `b = 1`
        //   exactly when `2ρ > q` (`q` is odd, so `2ρ = q` cannot happen).
        //   `ρ` is the main-basis CRT reconstruction of `A₀`'s `q_i` residues —
        //   `L` wide multiply-adds, no division.
        //
        // STEP 2 — the quotient, by an exact RNS division chain. For a single
        //   prime, `⌊A/q_i⌋ = (A − [A]_{q_i})/q_i` is an EXACT integer division,
        //   and mod any modulus `g` coprime to `q_i` its residue is
        //       (A_g − [A]_{q_i}) · (q_i^{-1} mod g)   (mod g),
        //   pure word arithmetic. Iterating over `i = 0…L−1` gives
        //   `⌊⌊…⌊A₀/q_0⌋/q_1⌋…/q_{L−1}⌋ = ⌊A₀/q⌋ = D` (the floor-of-floor
        //   identity holds for every integer `A₀` and positive divisors). The
        //   `q_i` slot dies at step `i` (`q_i` is not invertible mod itself),
        //   which is exactly why `D` comes out in the AUXILIARY basis and has to
        //   be carried back — step 3.
        //
        // STEP 3 — exact base extension `P → q`, Shenoy–Kumaresan. Let
        //   `ω_j = [z_j·(P/p_j)^{-1}]_{p_j}` for `z := D + div_shift ∈ [0, P)`
        //   (bound (B1)/(B2) above). Then `Σ_j ω_j·(P/p_j) = z + α·P` with
        //   `α ∈ [0, num_rs)` because every `ω_j < p_j`. Evaluating that sum mod
        //   the REDUNDANT modulus `m̃` — for which `z mod m̃` is known, because
        //   `m̃` is carried through steps 1–2 as an extra residue — gives
        //       α ≡ (Σ_j ω_j·(P/p_j) − z) · P^{-1}   (mod m̃),
        //   and since `0 ≤ α < num_rs < m̃` that residue IS `α`. Subtracting
        //   `α·(P mod q_i)` from the same sum evaluated mod `q_i` yields
        //   `z mod q_i` exactly. No approximation, no error term to bound: the
        //   only inequalities are (B1), (B2) and `num_rs < m̃`, all comptime.
        //
        // Finally `⌊t/q·T⌉ mod q_i = z − div_shift + b (mod q_i)`.

        /// One coefficient of the RNS rescale. `aq` are `A₀ = t·T`'s residues
        /// in the main basis (consumed), `ar`/`ask` the same in the auxiliary
        /// sub-basis and mod `m̃`. Writes `⌊t/q·T⌉ mod q_i` into `out`.
        fn rescaleCoeff(
            self: *const Self,
            aq: *[L]u64,
            ar: *[num_rs]u64,
            ask: *u64,
            out: *[L]u64,
        ) void {
            // STEP 1 — rounding bit from ρ = [t·T]_q.
            const rho = self.reconstruct(aq);
            const b: u64 = @intFromBool(2 * rho > q_product);

            // STEP 2 — divide out q_0 … q_{L−1}, exactly, one prime at a time.
            for (0..L) |i| {
                const rho_i = aq[i]; // [A_i]_{q_i}
                for (i + 1..L) |k| {
                    const mk = &self.engines[k].modulus;
                    aq[k] = mk.mul(ma.subMod(aq[k], mk.reduce(rho_i), self.primes[k]), self.qinv_q[i][k]);
                }
                for (0..num_rs) |j| {
                    const p = self.aux_primes[j];
                    const mp = &self.aux_engines[j].modulus;
                    ar[j] = mp.mul(ma.subMod(ar[j], mp.reduce(rho_i), p), self.qinv_rs[i][j]);
                }
                const msk = &self.sk_engine.modulus;
                ask.* = msk.mul(ma.subMod(ask.*, msk.reduce(rho_i), self.sk_prime), self.qinv_sk[i]);
            }

            // z = D + div_shift ∈ [0, 2·div_shift] ⊂ [0, P).
            var omega: [num_rs]u64 = undefined;
            for (0..num_rs) |j| {
                const p = self.aux_primes[j];
                const z_j = ma.addMod(ar[j], self.shift_rs[j], p);
                omega[j] = self.aux_engines[j].modulus.mul(z_j, self.rs_hat_inv[j]);
            }
            const z_sk = ma.addMod(ask.*, self.shift_sk, self.sk_prime);

            // STEP 3a — α, via the redundant modulus.
            const msk = &self.sk_engine.modulus;
            var sum_sk: u64 = 0;
            for (0..num_rs) |j| {
                sum_sk = ma.addMod(sum_sk, msk.mul(omega[j], self.rs_hat_sk[j]), self.sk_prime);
            }
            const alpha = msk.mul(ma.subMod(sum_sk, z_sk, self.sk_prime), self.rs_inv_sk);

            // STEP 3b — z mod q_i, then unshift and add the rounding bit.
            for (0..L) |i| {
                const qi = self.primes[i];
                const mi = &self.engines[i].modulus;
                var s: u64 = 0;
                for (0..num_rs) |j| s = ma.addMod(s, mi.mul(omega[j], self.rs_hat_q[j][i]), qi);
                const z_i = ma.subMod(s, mi.mul(alpha, self.rs_mod_q[i]), qi);
                out[i] = ma.addMod(ma.subMod(z_i, self.shift_q[i], qi), b, qi);
            }
        }

        /// Homomorphic multiply with the tensor AND the `⌊t/q·…⌉` rescale in
        /// RNS — the BEHZ/HPS shape. The exact integer tensor is never
        /// materialised and no big-integer division is performed: the only wide
        /// arithmetic left is the `[0,q)` CRT lift of the four INPUT components
        /// (needed to decide the centering `v > q/2`) and the per-coefficient
        /// reconstruction of `ρ` for the rounding bit — both `O(L)` multiply-adds.
        ///
        /// Bit-identical to `mulExactRef` by construction (see the derivation
        /// above), and asserted so by the differential test.
        pub fn mulBehz(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            var tq: [3]Ring = undefined;
            var ta: [3][num_behz][N]u64 = undefined;
            self.tensorAll(x, y, &tq, &ta);
            var outc: [3]Ring = undefined;
            for (0..3) |c| outc[c] = self.rescaleRns(&tq[c], &ta[c]);
            return .{ .components = outc, .len = 3 };
        }

        /// The exact integer tensor `(c0d0, c0d1+c1d0, c1d1)` expressed in
        /// residues over BOTH the main basis (`tq`) and the BEHZ auxiliary
        /// sub-basis plus `m̃` (`ta`). Split out of `mulBehz` so `bench.zig` can
        /// time the tensor and the rescale separately.
        pub fn tensorAll(
            self: *const Self,
            x: *const Ciphertext,
            y: *const Ciphertext,
            tq: *[3]Ring,
            ta: *[3][num_behz][N]u64,
        ) void {
            std.debug.assert(x.len == 2 and y.len == 2);
            const x0 = self.rawCoeffs(&x.components[0]);
            const x1 = self.rawCoeffs(&x.components[1]);
            const y0 = self.rawCoeffs(&y.components[0]);
            const y1 = self.rawCoeffs(&y.components[1]);

            // Auxiliary sub-basis + `m̃`: needs the CENTERED representatives,
            // hence the `[0,q)` lift above.
            for (0..num_behz) |k| {
                const eng = if (k < num_rs) &self.aux_engines[k] else &self.sk_engine;
                const qg = if (k < num_rs) self.q_mod_aux[k] else self.q_mod_sk;
                tensorModulus(eng, qg, &x0, &x1, &y0, &y1, &ta[0][k], &ta[1][k], &ta[2][k]);
            }

            // Main basis: centering is INVISIBLE here — it shifts each
            // representative by a multiple of `q`, which is `0 mod q_i` — so
            // this is an ordinary `R_{q_i}` ring tensor, no lift involved.
            var a0 = x.components[0];
            var a1 = x.components[1];
            var b0 = y.components[0];
            var b1 = y.components[1];
            a0.toNtt(&self.engines);
            a1.toNtt(&self.engines);
            b0.toNtt(&self.engines);
            b1.toNtt(&self.engines);
            tq.* = .{ a0, a0, a1 };
            tq[0].mulPointwise(&b0, &self.engines);
            tq[1].mulPointwise(&b1, &self.engines);
            var cross = a1;
            cross.mulPointwise(&b0, &self.engines);
            tq[1].addAssign(&cross, &self.primes);
            tq[2].mulPointwise(&b1, &self.engines);
            for (tq) |*r| r.fromNtt(&self.engines);
        }

        /// `⌊t/q · T⌉ mod q` for one whole tensor component, from residues
        /// only. The replacement for `rescaleTensor` — same value, no exact
        /// integer, no big-integer division.
        pub fn rescaleRns(self: *const Self, tq: *const Ring, ta: *const [num_behz][N]u64) Ring {
            var out = Ring.zero(.coeff);
            for (0..N) |j| {
                // A₀ = t·T for this coefficient, in every basis.
                var aq: [L]u64 = undefined;
                for (0..L) |i| aq[i] = self.engines[i].modulus.mul(self.t_mod_q[i], tq.limbs[i][j]);
                var ar: [num_rs]u64 = undefined;
                for (0..num_rs) |k| ar[k] = self.aux_engines[k].modulus.mul(self.t_mod_rs[k], ta[k][j]);
                var ask: u64 = self.sk_engine.modulus.mul(self.t_mod_sk, ta[num_rs][j]);
                var res: [L]u64 = undefined;
                self.rescaleCoeff(&aq, &ar, &ask, &res);
                for (0..L) |i| out.limbs[i][j] = res[i];
            }
            return out;
        }

        /// The ORIGINAL `O(N²)` exact-integer schoolbook multiply, kept as the
        /// differential ORACLE for `mulRnsNtt`/`mulBehz` — and, below
        /// `ntt_tensor_min_degree`, as the path `mul` actually takes.
        pub fn mulExactRef(self: *const Self, x: *const Ciphertext, y: *const Ciphertext) Ciphertext {
            std.debug.assert(x.len == 2 and y.len == 2);
            const x0 = self.centeredCoeffs(&x.components[0]);
            const x1 = self.centeredCoeffs(&x.components[1]);
            const y0 = self.centeredCoeffs(&y.components[0]);
            const y1 = self.centeredCoeffs(&y.components[1]);
            var t0 = [_]TensorI{0} ** N;
            var t1 = [_]TensorI{0} ** N;
            var t2 = [_]TensorI{0} ** N;
            negaMulAcc(&x0, &y0, &t0);
            negaMulAcc(&x0, &y1, &t1);
            negaMulAcc(&x1, &y0, &t1);
            negaMulAcc(&x1, &y1, &t2);
            return .{ .components = .{
                self.rescaleTensor(&t0),
                self.rescaleTensor(&t1),
                self.rescaleTensor(&t2),
            }, .len = 3 };
        }

        /// Relinearise a 3-component ciphertext back to 2 via the relin key:
        /// digit-decompose `c2 = Σ_i w^i·d_i` (exact, digits in `[0,w)`), then
        /// `(c0', c1') = (c0 + Σ d_i·b_i, c1 + Σ d_i·a_i)`. Correctness:
        ///   c0' + c1'·s = c0 + c1·s + Σ d_i·(b_i + a_i·s)
        ///               = c0 + c1·s + Σ d_i·(w^i·s² − e_i)
        ///               = c0 + c1·s + c2·s² − Σ d_i·e_i ,
        /// i.e. the phase is PRESERVED up to the key-switch noise
        /// `‖Σ d_i·e_i‖ ≤ relin_digits·N·(w−1)` — the `c2·s²` term is replaced
        /// by an encryption of the same value under `s`.
        pub fn relinearize(self: *const Self, ct: *const Ciphertext, rlk: *const RelinKey) Ciphertext {
            std.debug.assert(ct.len == 3);
            // Exact base-w digits of every coefficient of c2.
            var digits: [relin_digits][N]u64 = undefined;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = ct.components[2].limbs[i][j];
                var v: QU = self.reconstruct(&res); // [0, q)
                for (0..relin_digits) |i| {
                    digits[i][j] = @intCast(v & (relin_base - 1));
                    v >>= relin_base_log2;
                }
            }
            var c0 = ct.components[0];
            var c1 = ct.components[1];
            for (0..relin_digits) |i| {
                // d_i as a ring element: the same small integer digit per
                // coefficient across all limbs (its residues), like the
                // ternary sampler.
                var d = Ring.zero(.coeff);
                for (0..L) |l| {
                    const m = &self.engines[l].modulus;
                    for (0..N) |j| d.limbs[l][j] = m.reduce(digits[i][j]);
                }
                var tb = d.mul(&rlk.b[i], &self.engines);
                c0.addAssign(&tb, &self.primes);
                var ta = d.mul(&rlk.a[i], &self.engines);
                c1.addAssign(&ta, &self.primes);
            }
            return .{ .components = .{ c0, c1, Ring.zero(.coeff) }, .len = 2 };
        }

        /// Remaining noise budget (bits) of `ct` under `sk`:
        /// `⌊log2(q / (2·‖v‖_∞))⌋` where `v = centered(phase − Δ·m)` and `m`
        /// is the decrypted plaintext; `0` == exhausted (decryption failure
        /// territory). Decryption stays exact while `t·‖v‖ + r_t·‖m‖ < q/2`,
        /// i.e. while the budget is comfortably above `log2 t`.
        pub fn noiseBudget(self: *const Self, sk: *const SecretKey, ct: *const Ciphertext) u32 {
            // phase = Σ_i c_i·s^i in R_q (same accumulation as decrypt).
            var acc = ct.components[0];
            if (ct.len >= 2) {
                var spow = sk.s;
                var term = ct.components[1].mul(&spow, &self.engines);
                acc.addAssign(&term, &self.primes);
                var i: usize = 2;
                while (i < ct.len) : (i += 1) {
                    spow = spow.mul(&sk.s, &self.engines);
                    var t2 = ct.components[i].mul(&spow, &self.engines);
                    acc.addAssign(&t2, &self.primes);
                }
            }
            const half = q_product / 2;
            var vmax: QU = 0;
            const qr: QRescale = q_product;
            for (0..N) |j| {
                var res: [L]u64 = undefined;
                for (0..L) |i| res[i] = acc.limbs[i][j];
                const phase = self.reconstruct(&res); // [0, q)
                // m_j exactly as decrypt recovers it (round half up, mod t).
                const rounded = (2 * @as(QRescale, P.t) * @as(QRescale, phase) + qr) / (2 * qr);
                const m_j: QU = @intCast(rounded % @as(QRescale, P.t));
                const dm = delta * m_j; // < q (m_j ≤ t−1, Δ·(t−1) < q)
                const d = (phase + q_product - dm) % q_product;
                const v = if (d > half) q_product - d else d; // |centered|
                vmax = @max(vmax, v);
            }
            if (vmax == 0) return @intCast(std.math.log2_int(QU, q_product / 2));
            const ratio = q_product / (2 * vmax);
            if (ratio <= 1) return 0;
            return @intCast(std.math.log2_int(QU, ratio));
        }
    };
}

// ── tests: the REAL, ungated scheme surface (types + add) ─────────────────────

const testing = std.testing;

test "instance builds and exposes real ring add on ciphertext components" {
    const B = Bfv(params.test_tiny);
    const inst = try B.init();
    try testing.expectEqual(@as(usize, 8), B.degree);
    try testing.expectEqual(@as(usize, 2), B.num_primes);

    // Build two "ciphertexts" directly from ring elements (no encrypt yet) and
    // confirm `add` is exactly component-wise ring addition — a real op today.
    const primes = [_]u64{ 17, 97 };
    var a = B.Ciphertext{ .components = .{
        B.Ring.fromCoeffs(&primes, .{ [_]u64{ 1, 2, 3, 4, 5, 6, 7, 8 }, [_]u64{ 1, 1, 1, 1, 1, 1, 1, 1 } }),
        B.Ring.fromCoeffs(&primes, .{ [_]u64{0} ** 8, [_]u64{0} ** 8 }),
        B.Ring.zero(.coeff),
    }, .len = 2 };
    const b = B.Ciphertext{ .components = .{
        B.Ring.fromCoeffs(&primes, .{ [_]u64{ 16, 16, 16, 16, 16, 16, 16, 16 }, [_]u64{ 96, 96, 96, 96, 96, 96, 96, 96 } }),
        B.Ring.fromCoeffs(&primes, .{ [_]u64{0} ** 8, [_]u64{0} ** 8 }),
        B.Ring.zero(.coeff),
    }, .len = 2 };
    const c = inst.add(&a, &b);
    try testing.expectEqual(@as(usize, 2), c.numComponents());
    try testing.expectEqual(@as(u64, 0), c.components[0].limbs[0][0]); // (1+16) mod 17
    try testing.expectEqual(@as(u64, 0), c.components[0].limbs[1][0]); // (1+96) mod 97
    // sub is the inverse
    const back = inst.sub(&c, &b);
    try testing.expect(back.components[0].eql(&a.components[0]));
}

test "gate state after Part 3: both scheme cores ON" {
    // Part 2 turned on keyGen/encrypt/decrypt; Part 3 turned on the Fable
    // mul/relinearize/noiseBudget noise-management core.
    try testing.expect(gate.scheme_core_implemented);
    try testing.expect(gate.fable_core_implemented);
}

test "SecretKey.deinit zeroes the secret ring" {
    const B = Bfv(params.test_tiny);
    const inst = try B.init();
    var prng = std.Random.DefaultPrng.init(0xBEEF);
    const rnd = prng.random();
    var kp = inst.keyGenForTest(rnd);
    // Sanity: the freshly generated ternary key is not all-zero (astronomically
    // unlikely for a real key, and this instance's seed is fixed).
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&kp.sk), 0));
    kp.sk.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&kp.sk), 0));
}

// ── the RNG seam (B6) ─────────────────────────────────────────────────────────

/// Type of a function's LAST parameter, or `null` if that parameter is itself
/// generic. Used by the seam test below to read a signature at comptime.
fn lastParamType(comptime F: type) ?type {
    const p = @typeInfo(F).@"fn".params;
    return p[p.len - 1].type;
}

test "RNG seam: keyGen/encrypt/genRelinKey take std.Io, only the ForTest twins take std.Random" {
    const B = Bfv(params.test_tiny);
    // The point of this test is the SIGNATURE, not the value. `std.Random` is a
    // vtable — `DefaultPrng.init(0).random()` is indistinguishable from a CSPRNG
    // at the call site — and with a predictable stream `encrypt` leaks the
    // plaintext (`c0 − p0·u − e0 = Δ·m`, no secret key needed) and `genRelinKey`
    // leaks `s²` to the evaluator. These entry points draw through
    // `entropy.SecureSource`, fail-closed on `std.Io.randomSecure` — not
    // `std.Random.IoSource`, which would bind the silently-degrading
    // `std.Io.random`. Reintroducing a bare `std.Random` parameter would make
    // the whole class of failure trivial again.
    inline for (.{ @TypeOf(B.keyGen), @TypeOf(B.encrypt), @TypeOf(B.genRelinKey) }) |F| {
        try testing.expect(lastParamType(F).? == std.Io);
        try testing.expect(lastParamType(F).? != std.Random);
    }
    inline for (.{ @TypeOf(B.keyGenForTest), @TypeOf(B.encryptForTest), @TypeOf(B.genRelinKeyForTest) }) |F| {
        try testing.expect(lastParamType(F).? == std.Random);
    }
}

test "RNG seam: the std.Io path really draws entropy, and round-trips end to end" {
    const B = Bfv(params.test_tiny);
    const inst = try B.init();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A signature pin alone would pass over a body that ignores `io`. Two
    // keypairs from the same `io` must differ — `s` is a ternary vector of
    // length N=8 over 3 values plus a uniform mask `a` over the full modulus, so
    // an equal `pk` here means the entropy is not being read.
    const kp1 = inst.keyGen(io);
    const kp2 = inst.keyGen(io);
    try testing.expect(!kp1.pk.p0.eql(&kp2.pk.p0));

    // Same for `encrypt`: two encryptions of the SAME plaintext under the SAME
    // key must differ, which is exactly the property a seeded PRNG destroys.
    var pt = B.Plaintext.zero(params.test_tiny.t);
    pt.coeffs[0] = 3;
    pt.coeffs[1] = 1;
    const c1 = inst.encrypt(&kp1.pk, &pt, io);
    const c2 = inst.encrypt(&kp1.pk, &pt, io);
    try testing.expect(!c1.components[0].eql(&c2.components[0]));

    // And the production path is a working path, not just a typed one.
    const back = inst.decrypt(&kp1.sk, &c1);
    try testing.expectEqualSlices(u64, &pt.coeffs, &back.coeffs);

    // `genRelinKey` too — rows drawn from `io` differ between two keys.
    const rlk1 = inst.genRelinKey(&kp1.sk, io);
    const rlk2 = inst.genRelinKey(&kp1.sk, io);
    try testing.expect(!rlk1.a[0].eql(&rlk2.a[0]));
}
