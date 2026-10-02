// SPDX-License-Identifier: MIT

//! tfhe — TFHE/FHEW-style programmable **gate bootstrapping**: the scheme layer
//! over the mechanical ring/gadget/torus backbone. `Tfhe(P)` is an instance for
//! a compile-time parameter set `P` (GLWE dimension `k ≥ 1`).
//!
//! Model after Chillotti–Gama–Georgieva–Izabachène (TFHE, J. Cryptology 2020;
//! ePrint 2016/870) and Ducas–Micciancio (FHEW, EUROCRYPT 2015). Bootstrapping
//! turns leveled FHE into *unbounded-depth* FHE: after every gate we blind-
//! rotate a LUT to homomorphically re-decode the message and emit a FRESH
//! low-noise ciphertext, so noise never accumulates across depth.
//!
//! ## Layout — tfhe-rs's standard (non-Fourier) layout
//!
//! Every object here has the same coefficient order as tfhe-rs 1.8.1's
//! standard-domain containers, established by `tools/tfhers` as a black box
//! and pinned by `interop_test.zig`:
//!
//!   - LWE: `a_0 … a_{dim−1}, b`, with `b = ⟨a,s⟩ + μ + e`.
//!   - GLWE: `k` mask polynomials, then the body `b = Σ a_j·s_j + μ + e`.
//!   - GGSW: `ℓ` level matrices of `k+1` GLWE rows, the **least significant
//!     level first** (weight `q/B^ℓ`, … , `q/B`). Row `r < k` carries the
//!     gadget term `μ·q/B^level` in mask polynomial `r`, row `k` in the body.
//!   - Key-switch key: for each big-key coordinate `j`, `ℓ_ks` LWEs under the
//!     small key, least significant level first, row phase `s_ext[j]·q/B^level`.
//!   - Sample extraction reads coefficient 0; the big key is the GLWE key's
//!     polynomials concatenated.
//!
//! `ggswRowIndex` and `KeySwitchKey.row` are the only places the level order
//! appears; everything else indexes through them.
//!
//! ## Memory
//!
//! A bootstrap key is `n` GGSWs: for `tfhers_default` that is
//! `805·8·4·512·4 B ≈ 53 MB`, and the key-switch key `1536·5·806·4 B ≈ 25 MB`.
//! Both live on the heap (`allocator` parameters, `deinit(allocator)` wipes
//! and frees). `PreparedBootstrapKey` holds the bootstrap key in the NTT
//! domain (twice the size, `u64` residues) and is what a server evaluates
//! with: one external product costs `(k+1)·ℓ` forward and `k+1` inverse
//! transforms instead of `(k+1)²·ℓ` full products.
//!
//! ## Randomness — a security contract, not a portability tag
//!
//! Every production key-generation and encryption entry point takes
//! `io: std.Io` and draws through `entropy.SecureSource`, the fail-closed
//! `std.Random` adapter over `std.Io.randomSecure` (`modules/entropy`) — not
//! `std.Random.IoSource`, which binds `std.Io.random`. `std.Io.random` is
//! **contractually a CSPRNG** (`std/Io.zig`: "Obtains entropy from a
//! cryptographically secure pseudo-random number generator") but that same
//! doc comment documents a silent fallback to a weaker seed if the CSPRNG
//! source fails; the default `Io.Threaded` falls back to a pid+clock+ASLR
//! seed when `getrandom(2)` fails, e.g. under a seccomp policy that blocks
//! it. A bare `std.Random` parameter would
//! be worse still — it would accept `DefaultPrng.init(0)` at a call site that
//! looks identical to a correct one — and either failure mode here does not
//! weaken this scheme, it removes it. With `e` and `a` predictable,
//! `b = ⟨a,s⟩ + μ + e` is a linear system: `dim` ciphertexts recover the
//! secret key `s` by Gaussian elimination. The bootstrap and key-switch keys
//! are GLWE/GGSW encryptions of that same key and are *published* to the
//! evaluator, so predictable masking there hands the key over directly.
//! `entropy.SecureSource` aborts the process rather than draw from a source
//! that degraded — see its doc comment for why that is the right trade at a
//! `void`-returning `std.Random.fillFn`.
//!
//! The `…ForTest` twins keep a `std.Random` parameter, because the draw→value
//! KATs at the bottom of this file and the seeded end-to-end tests must stay
//! reproducible. They are named so that a production call site cannot use one
//! by accident. Taking `std.Io` (rather than reading OS entropy directly) keeps
//! the module `platform = .any`, the same shape `bbs`/`ibe`/`tlock` use.
//! Failing closed via `std.Io.randomSecure` was an open, tracked decision
//! (B7); it is now closed (`CONVENTIONS.md` §2.2), and this module takes it.
//!
//! ### Test-only guards and where they may sit
//!
//! Each `…ForTest` twin opens with `comptime if (!builtin.is_test)
//! @compileError(…)`, so a non-test build cannot reach a seeded-PRNG entry
//! point by typing a longer identifier. That guard may sit ONLY on the public
//! twin, never on a function the production wrapper calls, and the reason is
//! mechanical: **Zig analyses a callee through its caller.** An `lweKeyGen`
//! whose body called `lweKeyGenForTest` would drag the guard's `@compileError`
//! in with it and fail to compile in exactly the non-test build it exists to
//! serve. That is not hypothetical; it is what this module shipped until
//! 2026-08-13, invisible to CI because `builtin.is_test` is true for the whole
//! of `zig build test-tfhe`, so the deny branch never compiled.
//!
//! Hence the shape below: a PRIVATE `…Inner(…, random: std.Random)` holds the
//! body, the `std.Io` wrapper calls `…Inner` directly, and the public
//! `…ForTest` twin is a guard plus a call to the same `…Inner`. **An `…Inner`
//! calls `…Inner`, never a `…ForTest`** — otherwise the guard re-enters the
//! production path one level down.
//!
//! ## Constant-time posture (key path)
//!
//! `sampleBit`, and therefore `lweKeyGen`/`glweKeyGen`, are **fixed-cost and
//! branch-free**: one `u32` draw per key bit, the bit read arithmetically, no
//! rejection loop. Both error samplers consume a fixed number of draws and do
//! not branch on them (uniform: one multiply-shift; Gaussian: `noise.zig`'s
//! branch-free Box–Muller). `gadget.decompose` is branch-free too, though it
//! only ever sees ciphertext coefficients. (`clearBootstrap` is a test oracle
//! and is not constant time.)
//!
//! This is **source-level** constant time, measured under valgrind by
//! `ctgrind_harness.zig` (no secret-dependent branch or index in the targets it
//! drives). It is not a timing measurement, and it says nothing about operand-
//! dependent instruction latency.

const std = @import("std");
const builtin = @import("builtin");
const entropy = @import("entropy");
const params = @import("params.zig");
const torus = @import("torus.zig");
const polymod = @import("poly.zig");
const gadget = @import("gadget.zig");
const ntt = @import("ntt.zig");
const noise = @import("noise.zig");
const gate = @import("gate.zig");
const boolean = @import("boolean.zig");
const codec = @import("codec.zig");

const T = torus.Torus;
const Allocator = std.mem.Allocator;

/// Zero `buf`, then hand it back with `rawFree`. Not `allocator.free`: in the
/// safe modes that overwrites the buffer with `undefined` (0xAA) first, which
/// would hide from `free` — and from the test that checks it — whether the
/// key material was wiped.
fn freeWiped(comptime E: type, allocator: Allocator, buf: []E) void {
    const bytes = std.mem.sliceAsBytes(buf);
    std.crypto.secureZero(u8, bytes);
    if (bytes.len != 0) allocator.rawFree(bytes, .of(E), @returnAddress());
}

/// `Tfhe(P)` — a TFHE instance for the compile-time parameter set `P`.
pub fn Tfhe(comptime P: params.Params) type {
    const n = P.n;
    const k = P.k;
    const N = P.N;
    const ell = P.ell;
    const ell_ks = P.ell_ks;
    const bg_bits = P.bg_bits;
    const bks_bits = P.bks_bits;
    const big_dim = P.bigDim();
    const rows = P.ggswRows();
    const two_n = 2 * N;
    // Every entry point relies on these (exact prepared products, digits that
    // fit an i32, an NTT that exists for `N`); `init()` used to be the only
    // place that checked, and nothing forced a caller through it.
    comptime P.validate() catch |e| @compileError("tfhe: invalid parameter set: " ++ @errorName(e));

    return struct {
        const Self = @This();
        pub const parameters = P;
        pub const ring_degree = N;
        pub const glwe_dim = k;
        pub const lwe_dim = n;
        pub const big_lwe_dim = big_dim;
        pub const ggsw_rows = rows;
        /// Message scale for the programmable path's bit: `Δ = q/4`
        /// (padding-bit convention). The boolean gates use `±q/8` instead.
        pub const delta: T = 1 << 30;
        pub const delta_log: u6 = 30;
        pub const log_two_n: u6 = P.logTwoN();
        pub const Poly = polymod.Poly(N);
        const Engine = ntt.Engine(N);

        // ── ciphertext / key types ───────────────────────────────────────────

        /// LWE ciphertext of dimension `dim`: `(a ∈ Z_q^dim, b ∈ Z_q)`,
        /// `b = ⟨a,s⟩ + μ + e`.
        pub fn Lwe(comptime dim: usize) type {
            return struct { a: [dim]T, b: T };
        }
        /// Binary LWE secret key of dimension `dim`.
        pub fn LweKey(comptime dim: usize) type {
            return struct {
                s: [dim]T,

                /// Securely wipe the secret key. Fixed-size, no heap — zeroing
                /// the struct's bytes erases the secret bits `s`. Call when
                /// the key is no longer needed; left zeroed, must not be
                /// reused. Idempotent.
                pub fn deinit(self: *@This()) void {
                    std.crypto.secureZero(u8, std.mem.asBytes(self));
                }
            };
        }
        /// Input/output LWE (under the small key `s ∈ {0,1}^n`).
        pub const LweN = Lwe(n);
        /// LWE extracted from a GLWE (under the "big" key `s_ext ∈ {0,1}^{kN}`).
        pub const LweBig = Lwe(big_dim);

        /// GLWE secret key: `k` binary polynomials.
        pub const GlweKey = struct {
            s: [k]Poly,

            /// Securely wipe the secret key. Fixed-size, no heap. Idempotent.
            pub fn deinit(self: *GlweKey) void {
                std.crypto.secureZero(u8, std.mem.asBytes(self));
            }
        };
        /// GLWE ciphertext: `k` mask polynomials and the body
        /// `b = Σ mask_j·s_j + μ + e`.
        pub const Glwe = struct { mask: [k]Poly, body: Poly };

        /// GGSW ciphertext of a message `μ`: `(k+1)·ℓ` GLWE rows in tfhe-rs's
        /// order — see `ggswRowIndex`.
        pub const Ggsw = struct { rows: [rows]Glwe };

        /// Index into `Ggsw.rows` of gadget level `level` (0 = most
        /// significant, weight `q/B`) and component `r` (`r < k`: mask `r`;
        /// `r = k`: body). Levels are stored least significant first.
        pub fn ggswRowIndex(level: usize, r: usize) usize {
            return (ell - 1 - level) * (k + 1) + r;
        }

        /// Bootstrap key: a GGSW encryption of each LWE secret bit `s_i` under
        /// the GLWE key. Heap-allocated (`n` GGSWs).
        pub const BootstrapKey = struct {
            ggsw: []Ggsw,

            pub fn alloc(allocator: Allocator) Allocator.Error!BootstrapKey {
                return .{ .ggsw = try allocator.alloc(Ggsw, n) };
            }

            /// Wipe and free. Each row is an ENCRYPTION of a secret bit (not
            /// the bit itself), so this is defense-in-depth rather than a
            /// bare-secret erasure — still handled with the same discipline as
            /// the raw keys it is built from.
            pub fn deinit(self: *BootstrapKey, allocator: Allocator) void {
                freeWiped(Ggsw, allocator, self.ggsw);
                self.* = undefined;
            }
        };

        /// Key-switch key: for each big-key coordinate `j` and gadget level, an
        /// `LweN` encryption of `s_ext[j]·q/B_ks^{level+1}` under the small
        /// key. Heap-allocated, `kN·ℓ_ks` rows, least significant level first.
        pub const KeySwitchKey = struct {
            rows: []LweN,

            pub fn alloc(allocator: Allocator) Allocator.Error!KeySwitchKey {
                return .{ .rows = try allocator.alloc(LweN, big_dim * ell_ks) };
            }

            /// Row of big-key coordinate `j`, gadget `level` (0 = most
            /// significant).
            pub fn row(self: *const KeySwitchKey, j: usize, level: usize) *const LweN {
                return &self.rows[j * ell_ks + (ell_ks - 1 - level)];
            }
            fn rowMut(self: *KeySwitchKey, j: usize, level: usize) *LweN {
                return &self.rows[j * ell_ks + (ell_ks - 1 - level)];
            }

            /// Wipe and free (defense-in-depth: rows are encryptions).
            pub fn deinit(self: *KeySwitchKey, allocator: Allocator) void {
                freeWiped(LweN, allocator, self.rows);
                self.* = undefined;
            }
        };

        /// The bootstrap key in the NTT domain (`ntt.Engine(N)` residues mod
        /// the Goldilocks prime), as the blind rotation consumes it.
        ///
        /// **Exactness.** A prepared external product forms
        /// `Σ_row d_row · g_row` with signed digits `|d| ≤ B_g/2` and torus
        /// coefficients `g < 2^32` over `(k+1)·ℓ` rows of `N` terms, so every
        /// coefficient is an integer of magnitude `< 2^{preparedBoundLog2}`;
        /// `Params.validate` keeps that below `2^61 < p/2`, so the residue
        /// determines the integer and the result mod `2^32` is exact —
        /// bit-identical to `externalProduct` (asserted by a differential
        /// test). Unlike `ntt.Engine.mulTorus` no 16-bit split is needed:
        /// the digits are already small.
        pub const PreparedBootstrapKey = struct {
            /// `n·(k+1)·ℓ·(k+1)` transformed polynomials, index
            /// `((i·rows + row)·(k+1) + component)`.
            polys: [][N]u64,

            const per_ggsw = rows * (k + 1);

            /// Transform `bsk` (which the caller still owns).
            pub fn init(allocator: Allocator, bsk: *const BootstrapKey) Allocator.Error!PreparedBootstrapKey {
                var pk = try alloc(allocator);
                for (bsk.ggsw, 0..) |*g, i| pk.setGgsw(i, g);
                return pk;
            }

            /// Allocate without contents; fill every index with `setGgsw`.
            pub fn alloc(allocator: Allocator) Allocator.Error!PreparedBootstrapKey {
                return .{ .polys = try allocator.alloc([N]u64, n * per_ggsw) };
            }

            /// Transform `g` into slot `i` (the GGSW of key bit `i`).
            pub fn setGgsw(self: *PreparedBootstrapKey, i: usize, g: *const Ggsw) void {
                for (&g.rows, 0..) |*rw, r| {
                    for (0..k + 1) |c| {
                        const src = if (c < k) &rw.mask[c] else &rw.body;
                        const dst = &self.polys[(i * rows + r) * (k + 1) + c];
                        for (dst, src.c) |*d, v| d.* = v;
                        Engine.forward(dst);
                    }
                }
            }

            /// The standard-domain GGSW in slot `i`: the inverse transform of
            /// a residue `< 2^32` is that value.
            pub fn getGgsw(self: *const PreparedBootstrapKey, i: usize, out: *Ggsw) void {
                for (&out.rows, 0..) |*rw, r| {
                    for (0..k + 1) |c| {
                        var tmp = self.polys[(i * rows + r) * (k + 1) + c];
                        Engine.inverse(&tmp);
                        const dst = if (c < k) &rw.mask[c] else &rw.body;
                        for (&dst.c, tmp) |*d, v| d.* = @truncate(v);
                    }
                }
            }

            /// Recover the standard-domain key (for serialisation).
            pub fn toStandard(self: *const PreparedBootstrapKey, allocator: Allocator) Allocator.Error!BootstrapKey {
                const bsk = try BootstrapKey.alloc(allocator);
                for (bsk.ggsw, 0..) |*g, i| self.getGgsw(i, g);
                return bsk;
            }

            fn poly(self: *const PreparedBootstrapKey, i: usize, r: usize, c: usize) *const [N]u64 {
                return &self.polys[(i * rows + r) * (k + 1) + c];
            }

            /// Wipe and free.
            pub fn deinit(self: *PreparedBootstrapKey, allocator: Allocator) void {
                freeWiped([N]u64, allocator, self.polys);
                self.* = undefined;
            }

            /// `bsk.ggsw[i] ⊠ ct` — `externalProduct` in the transform domain.
            pub fn externalProduct(self: *const PreparedBootstrapKey, i: usize, ct: *const Glwe) Glwe {
                const d = decomposeGlwe(ct);
                var dt: [rows][N]u64 = undefined;
                for (&dt, &d) |*dst, *dp| {
                    for (dst, dp.c) |*o, coeff| o.* = residueOfDigit(coeff);
                    Engine.forward(dst);
                }
                var out: Glwe = undefined;
                for (0..k + 1) |c| {
                    var acc = [_]u64{0} ** N;
                    for (0..rows) |r| {
                        const g = self.poly(i, r, c);
                        for (&acc, dt[r], g) |*a, x, y| a.* = ntt.addMod(a.*, ntt.mulMod(x, y));
                    }
                    Engine.inverse(&acc);
                    const dst = if (c < k) &out.mask[c] else &out.body;
                    for (&dst.c, acc) |*o, v| o.* = ntt.recoverTorus(v);
                }
                return out;
            }

            /// `cmux` over `bsk.ggsw[i]`.
            pub fn cmux(self: *const PreparedBootstrapKey, i: usize, d0: *const Glwe, d1: *const Glwe) Glwe {
                const diff = glweSub(d1, d0);
                const sel = self.externalProduct(i, &diff);
                return glweAdd(d0, &sel);
            }

            /// `blindRotate` with this key.
            pub fn blindRotate(self: *const PreparedBootstrapKey, lut: *const Poly, b_tilde: usize, a_tilde: *const [n]usize) Glwe {
                const neg_b = (two_n - (b_tilde % two_n)) % two_n;
                const rotated_lut = lut.mulMonomial(neg_b);
                var acc = glweTrivial(&rotated_lut);
                for (0..n) |i| {
                    const rot = glweMulMonomial(&acc, a_tilde[i] % two_n);
                    acc = self.cmux(i, &acc, &rot);
                }
                return acc;
            }

            /// Programmable bootstrap WITHOUT the key switch: mod-switch,
            /// blind-rotate, sample-extract. The output is under the big key.
            pub fn bootstrapBig(self: *const PreparedBootstrapKey, lut: *const Poly, ct: *const LweN) LweBig {
                var a_tilde: [n]usize = undefined;
                for (&a_tilde, ct.a) |*at, ai| at.* = modSwitchScalar(ai);
                const acc = self.blindRotate(lut, modSwitchScalar(ct.b), &a_tilde);
                return sampleExtract(&acc);
            }

            /// Programmable gate bootstrap: `bootstrapBig` then key switch.
            pub fn bootstrap(self: *const PreparedBootstrapKey, ksk: *const KeySwitchKey, lut: *const Poly, ct: *const LweN) LweN {
                const big = self.bootstrapBig(lut, ct);
                return keySwitch(ksk, &big);
            }
        };

        /// A signed digit (as the two's-complement `u32` `decomposeGlwe`
        /// returns) as a canonical residue mod `p`.
        inline fn residueOfDigit(d: T) u64 {
            const v: u64 = @bitCast(@as(i64, @as(i32, @bitCast(d))));
            return v +% (ntt.p & (0 -% (v >> 63)));
        }

        /// The client's secret keys (boolean layer, `boolean.zig`).
        pub const ClientKey = boolean.ClientKey(Self);
        /// The evaluation key and the binary gates (`boolean.zig`).
        pub const ServerKey = boolean.ServerKey(Self);
        /// Byte encodings of keys and ciphertexts (`codec.zig`).
        pub const Codec = codec.Codec(Self);

        pub fn init() !Self {
            try P.validate();
            return .{};
        }

        // ── samplers (caller-supplied RNG) ───────────────────────────────────

        /// One secret key bit. **Fixed-cost and branch-free.**
        ///
        /// The previous body was `random.uintLessThan(u32, 2)`, which is
        /// `std.Random`'s Lemire sampler: it computes a rejection threshold
        /// and then *branches on the drawn value*. For `less_than = 2` the
        /// threshold reduces to 0, so the loop provably cannot run and the
        /// returned value is exactly the top bit of the single `u32` draw.
        /// Taking that bit directly is therefore **bit-identical** to the old
        /// sampler (the KATs at the bottom of this file were written against
        /// the old one and did not change), with no branch and no
        /// data-dependent draw count.
        fn sampleBit(random: std.Random) T {
            return random.int(u32) >> 31;
        }

        /// `sampleBit` for every element of `out`, from ONE read of
        /// `4·out.len` bytes. `std.Random.int(u32)` reads 4 bytes and decodes
        /// them little-endian, so this is value-for-value the per-bit loop —
        /// but one `fillFn` call instead of `out.len`: through
        /// `entropy.SecureSource` every call is a `getrandom(2)`, and a
        /// per-word loop made `tfhers_default` key generation take 20 s.
        fn sampleBits(random: std.Random, out: []T) void {
            fillUniform(random, out);
            for (out) |*x| x.* >>= 31;
        }

        /// Uniform torus words, one `fillFn` call (see `sampleBits`).
        fn fillUniform(random: std.Random, out: []T) void {
            random.bytes(std.mem.sliceAsBytes(out));
            for (out) |*x| x.* = std.mem.littleToNative(T, x.*);
        }

        /// The quantile map from a uniform 64-bit draw to an error in
        /// `[−B, B]`: multiply-shift, `v = ⌊u·(2B+1)/2^64⌋`. Fixed cost, no
        /// branch, residual bias `≈2^-53` in statistical distance.
        fn errorFromUniform(comptime B: u32, u: u64) T {
            comptime std.debug.assert(B < (1 << 30));
            const span: u64 = 2 * @as(u64, B) + 1;
            const v: u64 = @intCast((@as(u128, u) * span) >> 64);
            const e: i32 = @as(i32, @intCast(v)) - @as(i32, @intCast(B));
            return @bitCast(e);
        }

        /// One error from distribution `nz`. **Fixed-cost**: exactly
        /// `nz.drawBytes()` bytes of `random`, always.
        fn sampleNoise(comptime nz: params.Noise, random: std.Random) T {
            return switch (nz) {
                .uniform => |b| errorFromUniform(b, random.int(u64)),
                .gaussian => |s| blk: {
                    const d1 = random.int(u64);
                    const d2 = random.int(u64);
                    break :blk noise.gaussianTorus(comptime s * 4294967296.0, d1, d2);
                },
            };
        }

        /// The error distribution of an encryption under an LWE key of
        /// dimension `dim`: the small key's for `dim = n`, the GLWE key's
        /// otherwise (the big key is the GLWE key read as an LWE key).
        fn noiseFor(comptime dim: usize) params.Noise {
            return if (dim == n) P.lwe_noise else P.glwe_noise;
        }

        /// Bytes of `std.Random` one small-key error sample consumes.
        pub const error_draw_bytes: usize = P.lwe_noise.drawBytes();
        /// Test-visible aliases: the samplers are private, but the KATs that
        /// pin the draw→value mapping have to reach them.
        pub fn sampleErrorForTest(random: std.Random) T {
            return sampleNoise(P.lwe_noise, random);
        }
        pub fn errorFromUniformForTest(u: u64) T {
            return errorFromUniform(P.lwe_noise.uniform, u);
        }

        fn sampleUniformPoly(random: std.Random) Poly {
            var out: Poly = undefined;
            fillUniform(random, &out.c);
            return out;
        }

        /// `out.len` errors from `nz`, in one `fillFn` call: the same bytes,
        /// in the same order, as `out.len` calls of `sampleNoise`.
        fn sampleNoiseInto(comptime nz: params.Noise, random: std.Random, out: []T) void {
            const per = comptime nz.drawBytes() / 8;
            var draws: [256 * per]u64 = undefined;
            defer std.crypto.secureZero(u64, &draws);
            var done: usize = 0;
            while (done < out.len) {
                const m = @min(256, out.len - done);
                const d = draws[0 .. m * per];
                random.bytes(std.mem.sliceAsBytes(d));
                for (d) |*x| x.* = std.mem.littleToNative(u64, x.*);
                for (out[done..][0..m], 0..) |*e, i| e.* = switch (nz) {
                    .uniform => |b| errorFromUniform(b, d[i]),
                    .gaussian => |sg| noise.gaussianTorus(comptime sg * 4294967296.0, d[2 * i], d[2 * i + 1]),
                };
                done += m;
            }
        }

        // ── keygen ───────────────────────────────────────────────────────────
        //
        // Every randomness-consuming entry point in this file exists twice:
        //
        //   - `f(…, io: std.Io)`               — PRODUCTION. Draws through
        //     `entropy.SecureSource`, fail-closed on `std.Io.randomSecure`.
        //   - `fForTest(…, random: std.Random)` — TEST/KAT ONLY. Reproducible
        //     draws for the KATs and the seeded end-to-end tests.

        /// Generate a binary LWE secret key of dimension `dim` from `io`'s
        /// CSPRNG. If the bits were drawn from a seeded PRNG the key would be
        /// a deterministic function of that seed.
        pub fn lweKeyGen(comptime dim: usize, io: std.Io) LweKey(dim) {
            var src: entropy.SecureSource = .{ .io = io };
            return lweKeyGenInner(dim, src.interface());
        }

        /// The key generation itself. PRIVATE, and private is load-bearing:
        /// see the `Test-only guards and where they may sit` note above.
        fn lweKeyGenInner(comptime dim: usize, random: std.Random) LweKey(dim) {
            var key: LweKey(dim) = undefined;
            sampleBits(random, &key.s);
            return key;
        }

        /// TEST/KAT ONLY — `lweKeyGen` with caller-chosen draws.
        pub fn lweKeyGenForTest(comptime dim: usize, random: std.Random) LweKey(dim) {
            comptime testOnly();
            return lweKeyGenInner(dim, random);
        }

        /// Generate the binary GLWE secret key (`k` polynomials, polynomial
        /// 0's coefficients first) from `io`'s CSPRNG.
        pub fn glweKeyGen(io: std.Io) GlweKey {
            var src: entropy.SecureSource = .{ .io = io };
            return glweKeyGenInner(src.interface());
        }

        fn glweKeyGenInner(random: std.Random) GlweKey {
            var key: GlweKey = undefined;
            for (&key.s) |*sj| sampleBits(random, &sj.c);
            return key;
        }

        /// TEST/KAT ONLY — see `lweKeyGenForTest`.
        pub fn glweKeyGenForTest(random: std.Random) GlweKey {
            comptime testOnly();
            return glweKeyGenInner(random);
        }

        /// The LWE key `s_ext ∈ {0,1}^{kN}` obtained by concatenating the GLWE
        /// key's polynomials — the key under which `sampleExtract`'s output
        /// decrypts.
        pub fn extractGlweKey(gk: *const GlweKey) LweKey(big_dim) {
            var key: LweKey(big_dim) = undefined;
            for (gk.s, 0..) |sj, j| @memcpy(key.s[j * N ..][0..N], &sj.c);
            return key;
        }

        /// The guard every `…ForTest` twin opens with. Taking a caller-supplied
        /// `std.Random` is exactly how a seeded PRNG becomes key material, so
        /// production must not be able to reach a twin by typing a longer
        /// identifier. Tests compile with `is_test`, so the KATs are
        /// unaffected.
        fn testOnly() void {
            if (!builtin.is_test) @compileError(
                "this is a TEST-ONLY entry point: it takes a caller-supplied std.Random. Production code must use the std.Io entry point of the same name, which cannot be handed a seeded PRNG.",
            );
        }

        // ── LWE encrypt / decrypt ────────────────────────────────────────────

        /// Encrypt an already-scaled torus message `μ` under `key`, drawing the
        /// mask `a` and the noise `e` from `io`'s CSPRNG. With a predictable
        /// stream `b − ⟨a,s⟩ = μ + e` is a linear equation in `s` with no
        /// unknown noise left: `dim` such ciphertexts recover `s`.
        pub fn lweEncrypt(comptime dim: usize, key: *const LweKey(dim), mu: T, io: std.Io) Lwe(dim) {
            var src: entropy.SecureSource = .{ .io = io };
            return lweEncryptInner(dim, key, mu, src.interface());
        }

        fn lweEncryptInner(comptime dim: usize, key: *const LweKey(dim), mu: T, random: std.Random) Lwe(dim) {
            var ct: Lwe(dim) = undefined;
            var b: T = mu +% sampleNoise(noiseFor(dim), random);
            fillUniform(random, &ct.a);
            for (ct.a, key.s) |ai, si| b +%= ai *% si;
            ct.b = b;
            return ct;
        }

        /// TEST/KAT ONLY — `lweEncrypt` with caller-chosen draws.
        pub fn lweEncryptForTest(comptime dim: usize, key: *const LweKey(dim), mu: T, random: std.Random) Lwe(dim) {
            comptime testOnly();
            return lweEncryptInner(dim, key, mu, random);
        }

        /// Phase `b − ⟨a,s⟩ = μ + e`.
        pub fn lwePhase(comptime dim: usize, key: *const LweKey(dim), ct: *const Lwe(dim)) T {
            var acc: T = ct.b;
            for (ct.a, key.s) |ai, si| acc -%= ai *% si;
            return acc;
        }

        /// Decrypt a bit LWE (`Δ = q/4`).
        pub fn lweDecryptBit(comptime dim: usize, key: *const LweKey(dim), ct: *const Lwe(dim)) u32 {
            return torus.decode(lwePhase(dim, key, ct), delta_log, 2);
        }

        /// Trivial (noiseless, key-independent) LWE of `μ`: `(0, μ)`.
        pub fn lweTrivial(comptime dim: usize, mu: T) Lwe(dim) {
            return .{ .a = [_]T{0} ** dim, .b = mu };
        }
        pub fn lweAdd(comptime dim: usize, x: *const Lwe(dim), y: *const Lwe(dim)) Lwe(dim) {
            var out: Lwe(dim) = undefined;
            for (&out.a, x.a, y.a) |*o, p, q| o.* = p +% q;
            out.b = x.b +% y.b;
            return out;
        }
        pub fn lweSub(comptime dim: usize, x: *const Lwe(dim), y: *const Lwe(dim)) Lwe(dim) {
            var out: Lwe(dim) = undefined;
            for (&out.a, x.a, y.a) |*o, p, q| o.* = p -% q;
            out.b = x.b -% y.b;
            return out;
        }
        pub fn lweNeg(comptime dim: usize, x: *const Lwe(dim)) Lwe(dim) {
            var out: Lwe(dim) = undefined;
            for (&out.a, x.a) |*o, p| o.* = 0 -% p;
            out.b = 0 -% x.b;
            return out;
        }
        /// Multiply by a cleartext integer `c` (wrapping): phase `c·(μ + e)`.
        pub fn lweScalarMul(comptime dim: usize, x: *const Lwe(dim), c: T) Lwe(dim) {
            var out: Lwe(dim) = undefined;
            for (&out.a, x.a) |*o, p| o.* = p *% c;
            out.b = x.b *% c;
            return out;
        }
        /// Add a cleartext torus constant to the body.
        pub fn lweAddConstant(comptime dim: usize, x: *const Lwe(dim), mu: T) Lwe(dim) {
            var out = x.*;
            out.b +%= mu;
            return out;
        }

        // ── GLWE encrypt / decrypt ───────────────────────────────────────────

        /// Encrypt an already-scaled plaintext polynomial `μ`:
        /// `b = Σ mask_j·s_j + μ + e`, mask and noise from `io`'s CSPRNG. One
        /// GLWE ciphertext under a predictable stream is already an
        /// `N`-equation linear system in the key's coefficients.
        pub fn glweEncrypt(key: *const GlweKey, msg: *const Poly, io: std.Io) Glwe {
            var src: entropy.SecureSource = .{ .io = io };
            return glweEncryptInner(key, msg, src.interface());
        }

        /// Masks are drawn first (polynomial 0 first), then the `N` errors.
        fn glweEncryptInner(key: *const GlweKey, msg: *const Poly, random: std.Random) Glwe {
            var ct: Glwe = undefined;
            for (&ct.mask) |*m| m.* = sampleUniformPoly(random);
            var b = msg.*;
            for (&ct.mask, &key.s) |*m, *sj| {
                const prod = m.mul(sj);
                b.addAssign(&prod);
            }
            var e: [N]T = undefined;
            defer std.crypto.secureZero(T, &e);
            sampleNoiseInto(P.glwe_noise, random, &e);
            for (&b.c, e) |*x, ei| x.* +%= ei;
            ct.body = b;
            return ct;
        }

        /// TEST/KAT ONLY — `glweEncrypt` with caller-chosen draws.
        pub fn glweEncryptForTest(key: *const GlweKey, msg: *const Poly, random: std.Random) Glwe {
            comptime testOnly();
            return glweEncryptInner(key, msg, random);
        }

        /// Fresh encryption of the zero polynomial from `io`'s CSPRNG — the
        /// masking term every GGSW row is built on.
        pub fn glweEncryptZero(key: *const GlweKey, io: std.Io) Glwe {
            var src: entropy.SecureSource = .{ .io = io };
            return glweEncryptZeroInner(key, src.interface());
        }

        /// Calls `glweEncryptInner`, NOT `glweEncryptForTest` (see the guard
        /// note in the file comment).
        fn glweEncryptZeroInner(key: *const GlweKey, random: std.Random) Glwe {
            const z = Poly.zero();
            return glweEncryptInner(key, &z, random);
        }

        /// TEST/KAT ONLY — `glweEncryptZero` with caller-chosen draws.
        pub fn glweEncryptZeroForTest(key: *const GlweKey, random: std.Random) Glwe {
            comptime testOnly();
            return glweEncryptZeroInner(key, random);
        }

        /// Phase `b − Σ mask_j·s_j = μ + e`.
        pub fn glwePhase(key: *const GlweKey, ct: *const Glwe) Poly {
            var acc = ct.body;
            for (&ct.mask, &key.s) |*m, *sj| {
                const prod = m.mul(sj);
                acc.subAssign(&prod);
            }
            return acc;
        }

        /// Trivial (noiseless, key-independent) GLWE of `μ`: `(0, μ)`. Used to
        /// initialise the blind-rotation accumulator.
        pub fn glweTrivial(msg: *const Poly) Glwe {
            return .{ .mask = [_]Poly{Poly.zero()} ** k, .body = msg.* };
        }

        pub fn glweAdd(x: *const Glwe, y: *const Glwe) Glwe {
            var out: Glwe = undefined;
            for (&out.mask, &x.mask, &y.mask) |*o, *p, *q| o.* = p.add(q);
            out.body = x.body.add(&y.body);
            return out;
        }
        pub fn glweSub(x: *const Glwe, y: *const Glwe) Glwe {
            var out: Glwe = undefined;
            for (&out.mask, &x.mask, &y.mask) |*o, *p, *q| o.* = p.sub(q);
            out.body = x.body.sub(&y.body);
            return out;
        }
        /// Multiply a GLWE by the monomial `X^e` (rotate every component).
        pub fn glweMulMonomial(x: *const Glwe, e: usize) Glwe {
            var out: Glwe = undefined;
            for (&out.mask, &x.mask) |*o, *p| o.* = p.mulMonomial(e);
            out.body = x.body.mulMonomial(e);
            return out;
        }

        // ── GGSW / bootstrap key / key-switch key ────────────────────────────

        /// Encrypt a message polynomial `μ` as a GGSW from `io`'s CSPRNG. Each
        /// row is a fresh GLWE(0) plus the gadget term `μ·q/B_g^{level+1}` in
        /// the component the row selects. The messages this module encrypts as
        /// GGSW are the LWE secret key bits themselves (`bootstrapKeyGen`), and
        /// that key is published: predictable row masks hand over the key.
        pub fn ggswEncryptPoly(key: *const GlweKey, msg: *const Poly, io: std.Io) Ggsw {
            var src: entropy.SecureSource = .{ .io = io };
            return ggswEncryptPolyInner(key, msg, src.interface());
        }

        /// Rows are drawn in storage order (least significant level first).
        fn ggswEncryptPolyInner(key: *const GlweKey, msg: *const Poly, random: std.Random) Ggsw {
            var g: Ggsw = undefined;
            var lvl: usize = ell;
            while (lvl > 0) {
                lvl -= 1;
                var scaled = msg.scalarMul(torus.gadgetWeight(bg_bits, lvl));
                defer std.crypto.secureZero(T, &scaled.c);
                for (0..k + 1) |r| {
                    var rw = glweEncryptZeroInner(key, random);
                    if (r < k) rw.mask[r].addAssign(&scaled) else rw.body.addAssign(&scaled);
                    g.rows[ggswRowIndex(lvl, r)] = rw;
                }
            }
            return g;
        }

        /// TEST/KAT ONLY — `ggswEncryptPoly` with caller-chosen draws.
        pub fn ggswEncryptPolyForTest(key: *const GlweKey, msg: *const Poly, random: std.Random) Ggsw {
            comptime testOnly();
            return ggswEncryptPolyInner(key, msg, random);
        }

        /// GGSW of a scalar (constant polynomial), e.g. a secret key bit.
        pub fn ggswEncryptScalar(key: *const GlweKey, m: T, io: std.Io) Ggsw {
            var src: entropy.SecureSource = .{ .io = io };
            return ggswEncryptScalarInner(key, m, src.interface());
        }

        fn ggswEncryptScalarInner(key: *const GlweKey, m: T, random: std.Random) Ggsw {
            const c = Poly.constant(m);
            return ggswEncryptPolyInner(key, &c, random);
        }

        /// TEST/KAT ONLY — `ggswEncryptScalar` with caller-chosen draws.
        pub fn ggswEncryptScalarForTest(key: *const GlweKey, m: T, random: std.Random) Ggsw {
            comptime testOnly();
            return ggswEncryptScalarInner(key, m, random);
        }

        /// Bootstrap key: `GGSW(s_i)` for each LWE secret bit, under the GLWE
        /// key, every row's masking from `io`'s CSPRNG. This key is shipped to
        /// the evaluator; with a predictable stream it reads `s` off directly.
        pub fn bootstrapKeyGen(allocator: Allocator, lwe_key: *const LweKey(n), glwe_key: *const GlweKey, io: std.Io) Allocator.Error!BootstrapKey {
            var src: entropy.SecureSource = .{ .io = io };
            return bootstrapKeyGenInner(allocator, lwe_key, glwe_key, src.interface());
        }

        fn bootstrapKeyGenInner(allocator: Allocator, lwe_key: *const LweKey(n), glwe_key: *const GlweKey, random: std.Random) Allocator.Error!BootstrapKey {
            const bsk = try BootstrapKey.alloc(allocator);
            for (bsk.ggsw, lwe_key.s) |*g, si| g.* = ggswEncryptScalarInner(glwe_key, si, random);
            return bsk;
        }

        /// TEST/KAT ONLY — `bootstrapKeyGen` with caller-chosen draws.
        pub fn bootstrapKeyGenForTest(allocator: Allocator, lwe_key: *const LweKey(n), glwe_key: *const GlweKey, random: std.Random) Allocator.Error!BootstrapKey {
            comptime testOnly();
            return bootstrapKeyGenInner(allocator, lwe_key, glwe_key, random);
        }

        /// Key-switch key from the big (extracted) GLWE key to the small LWE
        /// key, every row encrypted from `io`'s CSPRNG. Its `kN·ℓ_ks` rows are
        /// published encryptions of the GLWE key's coefficients.
        pub fn keySwitchKeyGen(allocator: Allocator, glwe_key: *const GlweKey, small_key: *const LweKey(n), io: std.Io) Allocator.Error!KeySwitchKey {
            var src: entropy.SecureSource = .{ .io = io };
            return keySwitchKeyGenInner(allocator, glwe_key, small_key, src.interface());
        }

        /// Rows are drawn in storage order.
        fn keySwitchKeyGenInner(allocator: Allocator, glwe_key: *const GlweKey, small_key: *const LweKey(n), random: std.Random) Allocator.Error!KeySwitchKey {
            var big = extractGlweKey(glwe_key);
            defer big.deinit();
            var ksk = try KeySwitchKey.alloc(allocator);
            for (0..big_dim) |j| {
                var lvl: usize = ell_ks;
                while (lvl > 0) {
                    lvl -= 1;
                    const msg = big.s[j] *% torus.gadgetWeight(bks_bits, lvl);
                    ksk.rowMut(j, lvl).* = lweEncryptInner(n, small_key, msg, random);
                }
            }
            return ksk;
        }

        /// TEST/KAT ONLY — `keySwitchKeyGen` with caller-chosen draws.
        pub fn keySwitchKeyGenForTest(allocator: Allocator, glwe_key: *const GlweKey, small_key: *const LweKey(n), random: std.Random) Allocator.Error!KeySwitchKey {
            comptime testOnly();
            return keySwitchKeyGenInner(allocator, glwe_key, small_key, random);
        }

        // ── sample extraction / key switching (mechanical) ───────────────────

        /// Extract an `LweBig` encrypting coefficient 0 of the GLWE plaintext,
        /// under `extractGlweKey`. Per mask polynomial `j`, the negacyclic sign
        /// flip `a_ext[jN+i] = −a_j(X)_{N−i}` (`i ≥ 1`), `a_ext[jN] = a_j(X)_0`,
        /// so that `⟨a_ext, s_ext⟩ = (Σ a_j·s_j)_0`.
        pub fn sampleExtract(ct: *const Glwe) LweBig {
            var out: LweBig = undefined;
            out.b = ct.body.c[0];
            for (&ct.mask, 0..) |*m, j| {
                const o = out.a[j * N ..][0..N];
                o[0] = m.c[0];
                for (1..N) |i| o[i] = 0 -% m.c[N - i];
            }
            return out;
        }

        /// Key-switch an `LweBig` (under `s_ext`) down to an `LweN` (under the
        /// small key): `out = (0, b) − Σ_j Σ_level d_level(a_ext[j])·KSK[j][level]`.
        /// Byte-identical to tfhe-rs's `keyswitch_lwe_ciphertext` on the same
        /// key and input (`gadget.decompose` makes its digit choices).
        pub fn keySwitch(ksk: *const KeySwitchKey, ct: *const LweBig) LweN {
            var out: LweN = .{ .a = [_]T{0} ** n, .b = ct.b };
            for (0..big_dim) |j| {
                const digits = gadget.decompose(bks_bits, ell_ks, ct.a[j]);
                for (0..ell_ks) |lvl| {
                    const du: T = @bitCast(digits[lvl]);
                    const rw = ksk.row(j, lvl);
                    out.b -%= du *% rw.b;
                    for (&out.a, rw.a) |*om, rm| om.* -%= du *% rm;
                }
            }
            return out;
        }

        // ── message / LUT helpers (mechanical) ───────────────────────────────

        pub fn encodeBit(b: u32) T {
            return torus.encode(b, delta);
        }
        pub fn decodeBit(mu: T) u32 {
            return torus.decode(mu, delta_log, 2);
        }
        pub fn modSwitchScalar(x: T) usize {
            return torus.modSwitch(x, log_two_n);
        }

        /// Build the negacyclic LUT (test polynomial) for a function over a
        /// message space of `p = 2^p_log` slots on the torus, of which the lower
        /// half `p/2` are valid data messages. `outs[m]` is the (already
        /// Δ-scaled) desired output for data message `m ∈ [0, p/2)`. The upper
        /// half is filled by the negacyclic anti-symmetry `o(r+N) = −o(r)`, so
        /// blind-rotating by `−phase` and reading coefficient 0 yields
        /// `outs[decode(phase)]`.
        pub fn testPolynomial(comptime p_log: u6, outs: [1 << (p_log - 1)]T) Poly {
            const p = 1 << p_log;
            const half = p / 2;
            var lut = Poly.zero();
            for (0..N) |j| {
                // nearest of `p` message slots to torus position `j` (of 2N).
                const idx = ((j * p + N) / two_n) % p;
                lut.c[j] = if (idx < half) outs[idx] else 0 -% outs[idx - half];
            }
            return lut;
        }

        /// NOISELESS cleartext reference: the torus value blind rotation must
        /// place in coefficient 0 of the accumulator, given the input LWE and
        /// its secret key. `exp = (Σ ã_i·s_i) − b̃ (mod 2N)`; result =
        /// `(X^exp · lut)_0`. The anti-self-consistency oracle for `bootstrap`
        /// — a TEST reference that holds the secret key, not an evaluation
        /// path. The accumulation selects on the key bit through a mask, but
        /// the final `mulMonomial(rot)` branches and indexes on `rot`, which
        /// is derived from the key: NOT constant time, and not claimed to be.
        pub fn clearBootstrap(lut: *const Poly, ct: *const LweN, key: *const LweKey(n)) T {
            var rot: usize = (two_n - (modSwitchScalar(ct.b) % two_n)) % two_n; // X^{−b̃}
            for (ct.a, key.s) |ai, si| {
                const sel: usize = 0 -% @as(usize, si & 1);
                rot = (rot + (modSwitchScalar(ai) & sel)) % two_n;
            }
            return lut.mulMonomial(rot).constTerm();
        }

        /// Signed GLWE gadget decomposition consumed by the external product:
        /// `out[ggswRowIndex(level, r)]` is the level-`level` digit polynomial
        /// of component `r` (mask `r < k`, body `r = k`), as two's-complement
        /// torus elements. Pairs row-for-row with `Ggsw.rows`.
        pub fn decomposeGlwe(ct: *const Glwe) [rows]Poly {
            var out: [rows]Poly = undefined;
            for (0..k + 1) |r| {
                const src = if (r < k) &ct.mask[r] else &ct.body;
                for (src.c, 0..) |coeff, j| {
                    const d = gadget.decompose(bg_bits, ell, coeff);
                    for (0..ell) |lvl| out[ggswRowIndex(lvl, r)].c[j] = @bitCast(d[lvl]);
                }
            }
            return out;
        }

        // ── the core: external product, CMux, blind rotation, bootstrap ──────
        //
        // These four carry the TFHE soundness — the CMux selector, the
        // accumulator's rotation exponents, and the noise growth of the
        // external product. `PreparedBootstrapKey` has transform-domain twins
        // that a differential test holds to these bit for bit, and
        // `interop_test.zig` holds both to tfhe-rs's PBS output.

        /// GGSW ⊠ GLWE → GLWE: `out = Σ_row decomp[row] · ggsw.rows[row]`
        /// (scalar-poly × GLWE, accumulated component-wise). Result encrypts
        /// `μ_ggsw · plaintext(ct)` with controlled noise:
        ///
        ///   phase(out) = Σ_level Σ_{r<k} d_{level,r}·(e − μ·w_level·s_r)
        ///              + Σ_level d_{level,k}·(μ·w_level + e')
        ///              ≈ μ·(body − Σ_r mask_r·s_r) + noise
        ///
        /// (a row with the gadget term in mask `r` has phase `e − μ·w·s_r`).
        /// `Poly.mul` is exact mod `2^32`, so signed digits need no handling.
        pub fn externalProduct(ggsw: *const Ggsw, ct: *const Glwe) Glwe {
            const d = decomposeGlwe(ct);
            var out: Glwe = glweTrivial(&Poly.zero());
            for (0..rows) |r| {
                for (&out.mask, &ggsw.rows[r].mask) |*o, *g| {
                    const prod = d[r].mul(g);
                    o.addAssign(&prod);
                }
                const pb = d[r].mul(&ggsw.rows[r].body);
                out.body.addAssign(&pb);
            }
            return out;
        }

        /// CMux: `out = d0 + C ⊠ (d1 − d0)` — selects `d1` if `C` encrypts 1,
        /// else `d0`, homomorphically.
        pub fn cmux(ctrl: *const Ggsw, d0: *const Glwe, d1: *const Glwe) Glwe {
            const diff = glweSub(d1, d0);
            const sel = externalProduct(ctrl, &diff);
            return glweAdd(d0, &sel);
        }

        /// Blind rotation: `acc ← trivial(X^{−b̃}·lut)`; for each `i`,
        /// `acc ← CMux(bsk.ggsw[i], acc, X^{ã_i}·acc)`. Returns a GLWE
        /// encrypting `X^{−(b̃ − Σ ã_i s_i)}·lut`. The CMux runs for every `i`
        /// (when `ã_i = 0` the branches are equal and the product is zero).
        pub fn blindRotate(bsk: *const BootstrapKey, lut: *const Poly, b_tilde: usize, a_tilde: *const [n]usize) Glwe {
            const neg_b = (two_n - (b_tilde % two_n)) % two_n; // X^{−b̃}
            const rotated_lut = lut.mulMonomial(neg_b);
            var acc = glweTrivial(&rotated_lut);
            for (0..n) |i| {
                const rot = glweMulMonomial(&acc, a_tilde[i] % two_n); // X^{+ã_i}·acc
                acc = cmux(&bsk.ggsw[i], &acc, &rot);
            }
            return acc;
        }

        /// Programmable gate bootstrap with an unprepared key: modulus-switch
        /// `ct` into `[0,2N)`, blind-rotate `lut`, sample-extract coefficient
        /// 0, key-switch back to the small key. The reference for
        /// `PreparedBootstrapKey.bootstrap`, which a server should use.
        pub fn bootstrap(bsk: *const BootstrapKey, ksk: *const KeySwitchKey, lut: *const Poly, ct: *const LweN) LweN {
            var a_tilde: [n]usize = undefined;
            for (&a_tilde, ct.a) |*at, ai| at.* = modSwitchScalar(ai);
            const b_tilde = modSwitchScalar(ct.b);
            const acc = blindRotate(bsk, lut, b_tilde, &a_tilde);
            const big = sampleExtract(&acc);
            return keySwitch(ksk, &big);
        }
    };
}

// ── tests: the REAL scheme surface ───────────────────────────────────────────

const testing = std.testing;
const Toy = Tfhe(params.toy);
const toy_bound: u32 = params.toy.lwe_noise.uniform;
const N_big = params.toy.N;

test "instance builds and exposes the toy shape" {
    _ = try Toy.init();
    try testing.expectEqual(@as(usize, 256), Toy.ring_degree);
    try testing.expectEqual(@as(usize, 64), Toy.lwe_dim);
    try testing.expectEqual(@as(usize, 1), Toy.glwe_dim);
    try testing.expectEqual(@as(u6, 9), Toy.log_two_n);
}

test "LWE encrypt/decrypt round-trips a bit (bounded noise ≪ Δ/2)" {
    var prng = std.Random.DefaultPrng.init(1);
    const rnd = prng.random();
    const key = Toy.lweKeyGenForTest(64, rnd);
    for (0..50) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = Toy.lweEncryptForTest(64, &key, Toy.encodeBit(b), rnd);
        try testing.expectEqual(b, Toy.lweDecryptBit(64, &key, &ct));
    }
}

test "LWE linear operations act on the phase" {
    var prng = std.Random.DefaultPrng.init(12);
    const rnd = prng.random();
    const key = Toy.lweKeyGenForTest(64, rnd);
    const x = Toy.lweEncryptForTest(64, &key, 1 << 27, rnd);
    const y = Toy.lweEncryptForTest(64, &key, 5 << 26, rnd);
    const close = struct {
        fn f(got: T, want: T, tol: T) bool {
            return @min(got -% want, want -% got) <= tol;
        }
    }.f;
    try testing.expect(close(Toy.lwePhase(64, &key, &Toy.lweAdd(64, &x, &y)), 7 << 26, 2 * toy_bound));
    try testing.expect(close(Toy.lwePhase(64, &key, &Toy.lweSub(64, &x, &y)), 0 -% @as(T, 3 << 26), 2 * toy_bound));
    try testing.expect(close(Toy.lwePhase(64, &key, &Toy.lweNeg(64, &x)), 0 -% @as(T, 1 << 27), toy_bound));
    try testing.expect(close(Toy.lwePhase(64, &key, &Toy.lweScalarMul(64, &x, 3)), 3 << 27, 3 * toy_bound));
    try testing.expect(close(Toy.lwePhase(64, &key, &Toy.lweAddConstant(64, &x, 1 << 20)), (1 << 27) + (1 << 20), toy_bound));
    try testing.expectEqual(@as(T, 1 << 29), Toy.lwePhase(64, &key, &Toy.lweTrivial(64, 1 << 29)));
}

test "GLWE encrypt/decrypt round-trips a scaled plaintext" {
    var prng = std.Random.DefaultPrng.init(2);
    const rnd = prng.random();
    const key = Toy.glweKeyGenForTest(rnd);
    var msg = Toy.Poly.zero();
    for (&msg.c, 0..) |*c, i| c.* = Toy.encodeBit(@intCast(i & 1));
    const ct = Toy.glweEncryptForTest(&key, &msg, rnd);
    const phase = Toy.glwePhase(&key, &ct);
    for (phase.c, msg.c) |ph, m| {
        const err = @min(ph -% m, m -% ph);
        try testing.expect(err <= toy_bound);
    }
}

test "sampleExtract yields an LWE of coefficient 0 (decrypts under extracted key)" {
    var prng = std.Random.DefaultPrng.init(3);
    const rnd = prng.random();
    const gk = Toy.glweKeyGenForTest(rnd);
    const big_key = Toy.extractGlweKey(&gk);
    for (0..20) |_| {
        const b0 = rnd.uintLessThan(u32, 2);
        var msg = Toy.Poly.zero();
        msg.c[0] = Toy.encodeBit(b0);
        // other coeffs carry arbitrary scaled bits (must NOT leak into coeff 0)
        for (msg.c[1..]) |*c| c.* = Toy.encodeBit(rnd.uintLessThan(u32, 2));
        const ct = Toy.glweEncryptForTest(&gk, &msg, rnd);
        const lwe = Toy.sampleExtract(&ct);
        try testing.expectEqual(b0, Toy.lweDecryptBit(N_big, &big_key, &lwe));
    }
}

test "keySwitch preserves the message (big key → small key)" {
    var prng = std.Random.DefaultPrng.init(4);
    const rnd = prng.random();
    const gk = Toy.glweKeyGenForTest(rnd);
    const big_key = Toy.extractGlweKey(&gk);
    const small_key = Toy.lweKeyGenForTest(64, rnd);
    var ksk = try Toy.keySwitchKeyGenForTest(testing.allocator, &gk, &small_key, rnd);
    defer ksk.deinit(testing.allocator);
    for (0..20) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct_big = Toy.lweEncryptForTest(N_big, &big_key, Toy.encodeBit(b), rnd);
        const ct_small = Toy.keySwitch(&ksk, &ct_big);
        try testing.expectEqual(b, Toy.lweDecryptBit(64, &small_key, &ct_small));
    }
}

test "decomposeGlwe recomposes each component within the gadget error bound" {
    var prng = std.Random.DefaultPrng.init(5);
    const rnd = prng.random();
    const gk = Toy.glweKeyGenForTest(rnd);
    const ct = Toy.glweEncryptZeroForTest(&gk, rnd);
    const d = Toy.decomposeGlwe(&ct);
    const bound = gadget.maxError(params.toy.bg_bits, params.toy.ell);
    for (0..N_big) |j| {
        for (0..2) |r| {
            var acc: T = 0;
            for (0..params.toy.ell) |lvl| acc +%= d[Toy.ggswRowIndex(lvl, r)].c[j] *% torus.gadgetWeight(params.toy.bg_bits, lvl);
            const want = if (r == 0) ct.mask[0].c[j] else ct.body.c[j];
            try testing.expect(@min(acc -% want, want -% acc) <= bound);
        }
    }
}

test "gate flag ON: the four cores are implemented" {
    try testing.expect(gate.fable_core_implemented);
}

/// A `k = 2`, small-ring set: every `k`-indexed loop runs more than once.
const K2 = Tfhe(.{
    .n = 16,
    .k = 2,
    .N = 64,
    .bg_bits = 6,
    .ell = 3,
    .bks_bits = 3,
    .ell_ks = 6,
    .lwe_noise = .{ .uniform = 1 << 8 },
    .glwe_noise = .{ .uniform = 1 << 6 },
});

test "k = 2: GLWE, sample extraction and key switching use every mask polynomial" {
    var prng = std.Random.DefaultPrng.init(21);
    const rnd = prng.random();
    const gk = K2.glweKeyGenForTest(rnd);
    const big = K2.extractGlweKey(&gk);
    try testing.expectEqualSlices(T, &gk.s[1].c, big.s[64..128]);
    const small = K2.lweKeyGenForTest(16, rnd);
    var ksk = try K2.keySwitchKeyGenForTest(testing.allocator, &gk, &small, rnd);
    defer ksk.deinit(testing.allocator);
    for (0..20) |_| {
        const b = rnd.uintLessThan(u32, 2);
        var msg = K2.Poly.zero();
        msg.c[0] = K2.encodeBit(b);
        for (msg.c[1..]) |*c| c.* = K2.encodeBit(rnd.uintLessThan(u32, 2));
        const ct = K2.glweEncryptForTest(&gk, &msg, rnd);
        const ext = K2.sampleExtract(&ct);
        try testing.expectEqual(b, K2.lweDecryptBit(128, &big, &ext));
        try testing.expectEqual(b, K2.lweDecryptBit(16, &small, &K2.keySwitch(&ksk, &ext)));
    }
    // A GLWE that ignored mask polynomial 1 would decrypt under a key whose
    // second polynomial is zeroed; it must not.
    var half_key = gk;
    half_key.s[1] = K2.Poly.zero();
    var msg = K2.Poly.zero();
    msg.c[0] = K2.encodeBit(1);
    const ct = K2.glweEncryptForTest(&gk, &msg, rnd);
    var wrong: usize = 0;
    for (K2.glwePhase(&half_key, &ct).c, msg.c) |ph, m| {
        if (@min(ph -% m, m -% ph) > 1 << 20) wrong += 1;
    }
    try testing.expect(wrong > 32);
}

test "k = 2: the external product multiplies phases, and the GGSW rows sit where ggswRowIndex says" {
    var prng = std.Random.DefaultPrng.init(22);
    const rnd = prng.random();
    const gk = K2.glweKeyGenForTest(rnd);
    // Row phases: component r < k carries −w·s_r, the body row +w.
    const g1 = K2.ggswEncryptScalarForTest(&gk, 1, rnd);
    for (0..3) |lvl| {
        const w = torus.gadgetWeight(6, lvl);
        for (0..3) |r| {
            const ph = K2.glwePhase(&gk, &g1.rows[K2.ggswRowIndex(lvl, r)]);
            for (ph.c, 0..) |c, j| {
                const want: T = if (r < 2) 0 -% (w *% gk.s[r].c[j]) else if (j == 0) w else 0;
                try testing.expect(@min(c -% want, want -% c) <= 1 << 6);
            }
        }
    }
    for ([_]T{ 0, 1 }) |m| {
        const ggsw = K2.ggswEncryptScalarForTest(&gk, m, rnd);
        var msg = K2.Poly.zero();
        for (&msg.c, 0..) |*c, j| c.* = K2.encodeBit(@intCast(j & 1));
        const ct = K2.glweEncryptForTest(&gk, &msg, rnd);
        const out = K2.externalProduct(&ggsw, &ct);
        const ph = K2.glwePhase(&gk, &out);
        for (ph.c, msg.c) |c, want0| {
            const want = want0 *% m;
            try testing.expect(@min(c -% want, want -% c) < 1 << 26);
        }
    }
}

test "prepared external product and bootstrap are bit-identical to the reference" {
    var prng = std.Random.DefaultPrng.init(23);
    const rnd = prng.random();
    const gk = K2.glweKeyGenForTest(rnd);
    const small = K2.lweKeyGenForTest(16, rnd);
    var bsk = try K2.bootstrapKeyGenForTest(testing.allocator, &small, &gk, rnd);
    defer bsk.deinit(testing.allocator);
    var ksk = try K2.keySwitchKeyGenForTest(testing.allocator, &gk, &small, rnd);
    defer ksk.deinit(testing.allocator);
    var pk = try K2.PreparedBootstrapKey.init(testing.allocator, &bsk);
    defer pk.deinit(testing.allocator);

    // Arbitrary (not just well-formed) GLWE inputs, every key row.
    for (0..16) |i| {
        var ct: K2.Glwe = undefined;
        for (&ct.mask) |*m| {
            for (&m.c) |*c| c.* = rnd.int(T);
        }
        for (&ct.body.c) |*c| c.* = rnd.int(T);
        const want = K2.externalProduct(&bsk.ggsw[i], &ct);
        const got = pk.externalProduct(i, &ct);
        try testing.expectEqualSlices(u8, std.mem.asBytes(&want), std.mem.asBytes(&got));
    }
    const lut = K2.testPolynomial(2, .{ K2.encodeBit(0), K2.encodeBit(1) });
    for (0..4) |_| {
        const b = rnd.uintLessThan(u32, 2);
        const ct = K2.lweEncryptForTest(16, &small, K2.encodeBit(b), rnd);
        const want = K2.bootstrap(&bsk, &ksk, &lut, &ct);
        const got = pk.bootstrap(&ksk, &lut, &ct);
        try testing.expectEqualSlices(u8, std.mem.asBytes(&want), std.mem.asBytes(&got));
        try testing.expectEqual(b, K2.lweDecryptBit(16, &small, &got));
    }

    // toStandard inverts init.
    var back = try pk.toStandard(testing.allocator);
    defer back.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(bsk.ggsw), std.mem.sliceAsBytes(back.ggsw));
}

// ── the draw→secret mapping, pinned ──────────────────────────────────────────
//
// Nothing in this module pinned WHICH bit of a `std.Random` draw becomes a key
// bit, so a sampler rewrite could have swapped its arms and every existing test
// would still have passed — the key distribution stays uniform either way, and
// encrypt/decrypt round-trips under whatever key it produced. These KATs close
// that hole. They were written and run GREEN against the pre-CT samplers first,
// and are unchanged by the constant-time rewrite: that is the evidence the
// rewrite changed the *cost* of sampling and not the *result*.

/// A `std.Random` returning a fixed, formula-generated byte stream:
/// `byte(j) = ((j · 0x9E3779B1 mod 2^32) >> 11) & 0xFF`. Reproducible in any
/// language, so the frozen vectors below were derived independently rather
/// than captured from this module's own output. It also COUNTS the bytes it
/// hands out — which is how the tests observe that sampling is fixed-cost.
const ScriptedRandom = struct {
    pos: usize = 0,

    fn byteAt(j: usize) u8 {
        const x: u32 = @truncate(@as(u64, j) *% 0x9E3779B1);
        return @truncate(x >> 11);
    }
    fn fill(ptr: *anyopaque, buf: []u8) void {
        const self: *ScriptedRandom = @ptrCast(@alignCast(ptr));
        for (buf) |*b| {
            b.* = byteAt(self.pos);
            self.pos += 1;
        }
    }
    fn random(self: *ScriptedRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

fn bitOfHex(frozen: []const u8, i: usize) u32 {
    return (frozen[i / 8] >> @intCast(7 - (i % 8))) & 1;
}

test "KAT: lweKeyGen's draw→key-bit mapping (frozen) and its fixed cost" {
    var frozen: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&frozen, "c99999b333366666");

    var sc: ScriptedRandom = .{};
    const key = Toy.lweKeyGenForTest(64, sc.random());
    for (0..64) |i| {
        try testing.expectEqual(bitOfHex(&frozen, i), key.s[i]);
        // Independent derivation: bit `i` is the TOP bit of the little-endian
        // `u32` of draw `i`, i.e. the high bit of that draw's 4th byte.
        try testing.expectEqual(@as(u32, ScriptedRandom.byteAt(4 * i + 3) >> 7), key.s[i]);
    }
    // Exactly four bytes per key bit — no rejection loop drew a fifth. This is
    // the observable a data-dependent sampler would break.
    try testing.expectEqual(@as(usize, 4 * 64), sc.pos);
}

test "KAT: glweKeyGen's draw→key-bit mapping (frozen) and its fixed cost" {
    var frozen: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &frozen,
        "c99999b3333666664ccccd9999b3333266666ccccd999993333366666ccccc99",
    );
    var sc: ScriptedRandom = .{};
    const gk = Toy.glweKeyGenForTest(sc.random());
    for (0..N_big) |i| {
        try testing.expectEqual(bitOfHex(&frozen, i), gk.s[0].c[i]);
        try testing.expectEqual(@as(u32, ScriptedRandom.byteAt(4 * i + 3) >> 7), gk.s[0].c[i]);
    }
    try testing.expectEqual(@as(usize, 4 * N_big), sc.pos);
}

test "sampled key bits really are bits, and both keygens agree bit-for-bit" {
    // `lweKeyGen(N)` and `glweKeyGen` must sample the SAME way — the GLWE key
    // is read back out as an LWE key by `extractGlweKey`, so a divergence here
    // would be a silent scheme bug, not a style difference.
    var s1: ScriptedRandom = .{};
    var s2: ScriptedRandom = .{};
    const lk = Toy.lweKeyGenForTest(N_big, s1.random());
    const gk = Toy.glweKeyGenForTest(s2.random());
    try testing.expectEqualSlices(T, &lk.s, &gk.s[0].c);
    try testing.expectEqual(s1.pos, s2.pos);
    for (lk.s) |b| try testing.expect(b == 0 or b == 1);
}

test "KAT: the error sampler is fixed-cost and symmetric about zero" {
    var sc: ScriptedRandom = .{};
    var seen_neg = false;
    var seen_pos = false;
    const draws = 512;
    for (0..draws) |_| {
        const e: i32 = @bitCast(Toy.sampleErrorForTest(sc.random()));
        try testing.expect(e >= -@as(i32, @intCast(toy_bound)));
        try testing.expect(e <= @as(i32, @intCast(toy_bound)));
        if (e < 0) seen_neg = true;
        if (e > 0) seen_pos = true;
    }
    try testing.expect(seen_neg and seen_pos);
    // Fixed cost: exactly one draw per error, no rejection retry.
    try testing.expectEqual(@as(usize, draws * Toy.error_draw_bytes), sc.pos);
}

test "the error sampler's quantile map is unchanged, only its resolution" {
    // Unlike `sampleBit`, `sampleError` is NOT bit-identical to its old body:
    // it consumes 64 draw-bits instead of 32, so the same PRNG yields
    // different errors. That is a deliberate behaviour change and this test is
    // what stops it hiding an arm swap.
    //
    // The pre-rewrite map, written out here verbatim from `std.Random`'s
    // Lemire body (`uintLessThan(u32, 2B+1)` returns `⌊x·span/2^32⌋` whenever
    // it does not reject, and `intRangeAtMost` then adds `−B`):
    const B: u64 = toy_bound;
    const span: u64 = 2 * B + 1;
    const old = struct {
        fn map(x: u32, b: u64, sp: u64) i32 {
            const v: u64 = (@as(u64, x) * sp) >> 32;
            return @as(i32, @intCast(v)) - @as(i32, @intCast(b));
        }
    }.map;

    var prng = std.Random.DefaultPrng.init(909);
    const rnd = prng.random();
    for (0..20_000) |_| {
        const x = rnd.int(u32);
        // Same quantile, evaluated at 64-bit resolution, must give the SAME
        // value — the new map is the old map refined, not reflected.
        const got: i32 = @bitCast(Toy.errorFromUniformForTest(@as(u64, x) << 32));
        try testing.expectEqual(old(x, B, span), got);
    }
    // Endpoints and the sign convention, pinned by hand.
    try testing.expectEqual(-@as(i32, @intCast(B)), @as(i32, @bitCast(Toy.errorFromUniformForTest(0))));
    try testing.expectEqual(@as(i32, @intCast(B)), @as(i32, @bitCast(Toy.errorFromUniformForTest(std.math.maxInt(u64)))));
    // The midpoint draw is error 0 — a reflected sampler would still be
    // symmetric, but it would not fix these three points together with the
    // 20 000 quantile equalities above.
    try testing.expectEqual(@as(i32, 0), @as(i32, @bitCast(Toy.errorFromUniformForTest(1 << 63))));
}

test "deinit wipes the secret keys, and the heap keys before freeing them" {
    var prng = std.Random.DefaultPrng.init(6);
    const rnd = prng.random();

    var lwe_key = Toy.lweKeyGenForTest(64, rnd);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&lwe_key), 0));
    lwe_key.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&lwe_key), 0));

    var glwe_key = Toy.glweKeyGenForTest(rnd);
    try testing.expect(!std.mem.allEqual(u8, std.mem.asBytes(&glwe_key), 0));
    glwe_key.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&glwe_key), 0));

    // The heap keys are gone after `deinit`, so the check happens inside
    // `free`: this allocator records whether every freed buffer was zero.
    var wipe: WipeCheckingAllocator = .{ .backing = testing.allocator };
    const a = wipe.allocator();
    const gk2 = K2.glweKeyGenForTest(rnd);
    const small_key = K2.lweKeyGenForTest(16, rnd);
    var bsk = try K2.bootstrapKeyGenForTest(a, &small_key, &gk2, rnd);
    var pk = try K2.PreparedBootstrapKey.init(a, &bsk);
    bsk.deinit(a);
    pk.deinit(a);
    var ksk = try K2.keySwitchKeyGenForTest(a, &gk2, &small_key, rnd);
    ksk.deinit(a);
    try testing.expectEqual(@as(usize, 3), wipe.frees);
    try testing.expectEqual(@as(usize, 0), wipe.dirty_frees);
}

/// Delegates to `backing`, counting frees and frees of non-zero memory.
const WipeCheckingAllocator = struct {
    backing: Allocator,
    frees: usize = 0,
    dirty_frees: usize = 0,

    fn allocator(self: *WipeCheckingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = Allocator.noResize,
            .remap = Allocator.noRemap,
            .free = free,
        } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ra);
    }
    fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *WipeCheckingAllocator = @ptrCast(@alignCast(ctx));
        self.frees += 1;
        if (!std.mem.allEqual(u8, buf, 0)) self.dirty_frees += 1;
        self.backing.rawFree(buf, alignment, ra);
    }
};

// ── the RNG seam (B6) ────────────────────────────────────────────────────────

/// Type of a function's LAST parameter, or `null` if that parameter is itself
/// generic. Used by the seam test below to read a signature at comptime.
fn lastParamType(comptime F: type) ?type {
    const p = @typeInfo(F).@"fn".params;
    return p[p.len - 1].type;
}

test "RNG seam: every production keygen/encrypt takes std.Io, only the ForTest twins take std.Random" {
    // The point of this test is the SIGNATURE, not the value. `std.Random` is a
    // vtable — `DefaultPrng.init(0).random()` and a CSPRNG are indistinguishable
    // at a call site — so as long as a production entry point accepts one, a
    // consumer can silently generate an FHE secret key that is a function of a
    // seed. These entry points draw through `entropy.SecureSource`, fail-closed
    // on `std.Io.randomSecure` — not `std.Random.IoSource`, which would bind
    // the silently-degrading `std.Io.random`. If someone reintroduces a bare
    // `std.Random` parameter on any of these, this fails to compile or fails
    // here.
    inline for (.{
        @TypeOf(Toy.lweKeyGen), // generic in `dim`; the entropy parameter is still concrete
        @TypeOf(Toy.glweKeyGen),
        @TypeOf(Toy.lweEncrypt),
        @TypeOf(Toy.glweEncrypt),
        @TypeOf(Toy.glweEncryptZero),
        @TypeOf(Toy.ggswEncryptPoly),
        @TypeOf(Toy.ggswEncryptScalar),
        @TypeOf(Toy.bootstrapKeyGen),
        @TypeOf(Toy.keySwitchKeyGen),
    }) |F| {
        try testing.expect(lastParamType(F).? == std.Io);
        try testing.expect(lastParamType(F).? != std.Random);
    }
    // …and the reproducible twins keep `std.Random`, under a name a production
    // call site cannot use by accident.
    inline for (.{
        @TypeOf(Toy.lweKeyGenForTest),
        @TypeOf(Toy.glweKeyGenForTest),
        @TypeOf(Toy.lweEncryptForTest),
        @TypeOf(Toy.glweEncryptForTest),
        @TypeOf(Toy.glweEncryptZeroForTest),
        @TypeOf(Toy.ggswEncryptPolyForTest),
        @TypeOf(Toy.ggswEncryptScalarForTest),
        @TypeOf(Toy.bootstrapKeyGenForTest),
        @TypeOf(Toy.keySwitchKeyGenForTest),
    }) |F| {
        try testing.expect(lastParamType(F).? == std.Random);
    }
}

test "RNG seam: the std.Io path really draws entropy, and round-trips end to end" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A signature pin alone would pass over a body that ignores `io`. Two keys
    // drawn from the same `io` must differ: 64 independent bits each, so a
    // collision here is 2^-64 unless the entropy is not being read.
    const k1 = Toy.lweKeyGen(64, io);
    const k2 = Toy.lweKeyGen(64, io);
    try testing.expect(!std.mem.eql(T, &k1.s, &k2.s));
    const g1 = Toy.glweKeyGen(io);
    const g2 = Toy.glweKeyGen(io);
    try testing.expect(!std.mem.eql(T, &g1.s[0].c, &g2.s[0].c));

    // And the production path is a working path, not just a typed one.
    for (0..8) |b| {
        const bit: u32 = @intCast(b & 1);
        const ct = Toy.lweEncrypt(64, &k1, Toy.encodeBit(bit), io);
        try testing.expectEqual(bit, Toy.lweDecryptBit(64, &k1, &ct));
    }
    const msg = Toy.Poly.zero();
    const gct = Toy.glweEncrypt(&g1, &msg, io);
    for (Toy.glwePhase(&g1, &gct).c) |ph| {
        const err = @min(ph, 0 -% ph);
        try testing.expect(err <= toy_bound);
    }
}

test "bulk draws are value-for-value the per-sample samplers (uniform and Gaussian)" {
    const G = Tfhe(params.tfhers_default);
    inline for (.{ .{ Toy, params.toy.glwe_noise }, .{ G, params.tfhers_default.glwe_noise }, .{ G, params.tfhers_default.lwe_noise } }) |c| {
        const F = c[0];
        var s1: ScriptedRandom = .{};
        var s2: ScriptedRandom = .{};
        var bulk: [700]T = undefined; // crosses the 256-sample chunking twice
        F.sampleNoiseInto(c[1], s1.random(), &bulk);
        for (bulk) |e| try testing.expectEqual(F.sampleNoise(c[1], s2.random()), e);
        try testing.expectEqual(s1.pos, s2.pos);
    }
    var s1: ScriptedRandom = .{};
    var s2: ScriptedRandom = .{};
    var bits: [300]T = undefined;
    Toy.sampleBits(s1.random(), &bits);
    for (bits) |b| try testing.expectEqual(Toy.sampleBit(s2.random()), b);
    try testing.expectEqual(s1.pos, s2.pos);
}

test "encryptions carry the parameter set's error: right distribution, right width, LWE vs GLWE" {
    // Decryption tests pass on ciphertexts with NO error at all, and on errors
    // of the wrong width; that is a security failure, not a functional one.
    const stats = struct {
        fn sd(xs: []const T) f64 {
            var s: f64 = 0;
            var s2: f64 = 0;
            for (xs) |x| {
                const f: f64 = @floatFromInt(@as(i32, @bitCast(x)));
                s += f;
                s2 += f * f;
            }
            const n: f64 = @floatFromInt(xs.len);
            return @sqrt(s2 / n - (s / n) * (s / n));
        }
    };
    var prng = std.Random.DefaultPrng.init(41);
    const rnd = prng.random();
    var errs: [4096]T = undefined;

    // tfhers_default: LWE σ·2^32 ≈ 25 175, GLWE σ·2^32 ≈ 4.0.
    const G = Tfhe(params.tfhers_default);
    const lk = G.lweKeyGenForTest(805, rnd);
    for (errs[0..2048]) |*e| e.* = G.lwePhase(805, &lk, &G.lweEncryptForTest(805, &lk, 0, rnd));
    try testing.expectApproxEqRel(params.tfhers_default.lwe_noise.stddev(), stats.sd(errs[0..2048]), 0.06);
    const gk = G.glweKeyGenForTest(rnd);
    for (0..8) |i| {
        const ph = G.glwePhase(&gk, &G.glweEncryptZeroForTest(&gk, rnd));
        @memcpy(errs[i * 512 ..][0..512], &ph.c);
    }
    try testing.expectApproxEqRel(params.tfhers_default.glwe_noise.stddev(), stats.sd(&errs), 0.06);

    // toy: uniform in [−2^10, 2^10], σ = 2^10/√3, and never outside the bound.
    const tk = Toy.lweKeyGenForTest(64, rnd);
    for (&errs) |*e| e.* = Toy.lwePhase(64, &tk, &Toy.lweEncryptForTest(64, &tk, 0, rnd));
    try testing.expectApproxEqRel(params.toy.lwe_noise.stddev(), stats.sd(&errs), 0.05);
    for (errs) |e| try testing.expect(@abs(@as(i32, @bitCast(e))) <= toy_bound);
}
