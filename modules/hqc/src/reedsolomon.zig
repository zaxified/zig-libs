// SPDX-License-Identifier: MIT
//! reedsolomon — the [n1, k, delta] Reed-Solomon code over GF(2^8) that is
//! the OUTER code of HQC's Part-2 concatenated code (spec §3.4; reference
//! `src/ref/reed_solomon.c`/`reed_solomon.h`, root-finding delegated to
//! `src/common/fft.c`/`fft.h`).
//!
//! **Encode is real (Sonnet)**: `RS(p, generator).encode` is a direct,
//! mechanical port of the reference's systematic LFSR shift-register
//! encoder (`reed_solomon_encode`) — there is no algorithmic choice to
//! make, only bit-for-bit transcription, and it is numeric-KAT-pinned
//! byte-exact against the reference (see `kat_vectors_code.zig` /
//! `code_kat_test.zig`).
//!
//! **Decode is the Fable-hard RS half (now implemented)**:
//! `RS(p, generator).decode` ports the reference's `reed_solomon_decode`
//! six-step pipeline exactly — syndromes -> constant-time
//! Berlekamp-Massey error-locator polynomial (`compute_elp`) ->
//! additive-FFT root-finding (Gao-Mateer `fft`/`fft_retrieve_error_poly`,
//! NOT Chien search) -> error-evaluator polynomial z(x) -> Forney error
//! values (`compute_error_values`' constant-access-pattern bookkeeping)
//! -> correct + extract. See `decode`'s doc comment for the step-by-step
//! contract and the per-helper comments for the fft.c/reed_solomon.c
//! mapping. Exercised by the gated tests in `code_kat_test.zig`
//! (`gate.decoder_core_implemented`, now true).

const std = @import("std");
const params = @import("params.zig");
const gf = @import("gf256.zig");

/// hqc-128's Reed-Solomon generator polynomial coefficients (reference:
/// `RS_POLY_COEFS`, `src/ref/hqc-1/parameters.h`). Degree `2*delta = 30`,
/// so 31 coefficients: index 0 is the constant term, index 30 the leading
/// (monic) coefficient — always 1, per `compute_generator_poly`'s
/// construction (each factor `(x - alpha^i)` is monic, so the product is
/// too). These are PUBLIC, parameter-set-fixed constants (not derived
/// from any secret), transcribed verbatim from the reference header.
pub const generator_hqc128: [31]u8 = .{
    89,  69,  153, 116, 176, 117, 111, 75,  73,  233, 242, 233, 65, 210, 21,
    139, 103, 173, 67,  118, 105, 210, 174, 110, 74,  69,  228, 82, 255, 181,
    1,
};

/// hqc-192's Reed-Solomon generator polynomial. Degree `2*delta = 32`, 33
/// coefficients. Reference: `RS_POLY_COEFS`, `src/ref/hqc-3/parameters.h`.
pub const generator_hqc192: [33]u8 = .{
    45,  216, 239, 24,  253, 104, 27, 40,  107, 50, 163, 210, 227,
    134, 224, 158, 119, 13,  158, 1,  238, 164, 82, 43,  15,  232,
    246, 142, 50,  189, 29,  232, 1,
};

/// hqc-256's Reed-Solomon generator polynomial. Degree `2*delta = 58`, 59
/// coefficients. Reference: `RS_POLY_COEFS`, `src/ref/hqc-5/parameters.h`.
pub const generator_hqc256: [59]u8 = .{
    49,  167, 49,  39, 200, 121, 124, 91,  240, 63,  148, 71,  150,
    123, 87,  101, 32, 215, 159, 71,  201, 115, 97,  210, 186, 183,
    141, 217, 123, 12, 31,  243, 180, 219, 152, 239, 99,  141, 4,
    246, 191, 144, 8,  232, 47,  27,  141, 178, 130, 64,  124, 47,
    39,  188, 216, 48, 199, 187, 1,
};

/// The [n1, k, delta] Reed-Solomon code for one HQC parameter set,
/// specialized at comptime. `p.n1`/`p.delta`/`p.securityBytes()` (=
/// reference `PARAM_K`) come from `params.zig`; `generator` must be the
/// matching `generator_hqc1xx` constant above (its length is pinned to
/// `2*p.delta+1` by this function's own parameter type, so a mismatched
/// pairing is a compile error, not a runtime bug).
pub fn RS(comptime p: params.Params, comptime generator: [2 * p.delta + 1]u8) type {
    return struct {
        pub const n1 = p.n1;
        pub const k: usize = p.securityBytes();
        pub const delta = p.delta;

        /// n1 - k, the redundancy (parity) prefix length. Always exactly
        /// `2*delta` for every real HQC parameter set — the shortened-RS
        /// construction is built to guarantee this (spec §3.4); asserted
        /// at comptime rather than assumed.
        pub const redundancy = n1 - k;
        comptime {
            std.debug.assert(redundancy == 2 * delta);
        }

        pub const Codeword = [n1]u8;
        pub const Message = [k]u8;

        /// Systematic Reed-Solomon encode (reference: `reed_solomon_encode`).
        ///
        /// Implements a `redundancy`-stage linear feedback shift register
        /// with feedback taps `generator`, clocked once per message byte,
        /// MOST-significant message byte first (`msg[k-1-i]` — note this
        /// is index-reversed relative to the message's own byte order).
        /// After all `k` clocks, the register holds `msg(x) * x^redundancy
        /// mod g(x)` (the standard CRC-style systematic-encoding
        /// remainder); the codeword is that remainder followed by the
        /// unmodified message:
        ///
        ///   codeword = remainder(redundancy bytes) ‖ message(k bytes)
        ///
        /// This is the reference's own byte order — remainder FIRST, not
        /// the arguably more common message-first layout — and Part 3's
        /// KAT reproduction depends on getting this exactly right (see
        /// `kat_vectors_code.zig`'s `*_rs_*` vectors, which pin exactly
        /// this layout: e.g. the all-0xff-message vectors end in 16
        /// trailing 0xff bytes, the unmodified message, with everything
        /// before that being the LFSR remainder).
        pub fn encode(msg: Message) Codeword {
            var cdw: Codeword = [_]u8{0} ** n1;
            for (0..k) |i| {
                const gate_value = msg[k - 1 - i] ^ cdw[redundancy - 1];
                var tmp: [generator.len]u8 = undefined;
                for (0..generator.len) |j| tmp[j] = gf.mul(gate_value, generator[j]);
                var kk = redundancy - 1;
                while (kk > 0) : (kk -= 1) cdw[kk] = cdw[kk - 1] ^ tmp[kk];
                cdw[0] = tmp[0];
            }
            @memcpy(cdw[redundancy..], &msg);
            return cdw;
        }

        /// THE FABLE CORE (Reed-Solomon half). Decodes a received
        /// codeword `cdw` (the systematic layout `encode` produces,
        /// possibly with up to `delta` symbol errors introduced by the
        /// channel — HQC's own noisy Hamming-quasi-cyclic decryption
        /// step, not this module's concern) back to the original `k`-byte
        /// message.
        ///
        /// **Implemented algorithm — six steps, following the reference's
        /// `reed_solomon_decode` exactly (this is the full spec, not a
        /// hint; `lin1983error` = Lin & Costello, *Error Control Coding*,
        /// the reference's own cited source for both Berlekamp's
        /// algorithm and syndrome/error-evaluator theory):**
        ///
        ///  1. **Syndromes** (reference: `compute_syndromes`). Compute
        ///     `2*delta` syndromes `S_i = cdw[0] XOR-sum_{j=1}^{n1-1}
        ///     cdw[j] * alpha^(i*j)` for `i` in `[0, 2*delta)`, where
        ///     `alpha = 2` is the same field generator `gf256.zig` uses.
        ///     The reference precomputes `alpha^(i*j)` into a
        ///     `[2*delta][n1-1]` table (`alpha_ij_pow`,
        ///     `reed_solomon.h`) rather than calling `gf.exp`/`pow`
        ///     per-term; a from-scratch implementation may instead
        ///     compute `gf256.mul` repeatedly (functionally identical,
        ///     just not pre-tabulated) or port the literal table — either
        ///     is fine as long as the result is byte-exact, which is
        ///     checkable against `reed_solomon_decode`'s `#ifdef VERBOSE`
        ///     syndrome dump if a fresh reference intermediate-value trace
        ///     is captured (Part 1's `kat_vectors.zig` used the same
        ///     `intermediates_values`-file technique for the PRNG layer —
        ///     the RS/RM layer's reference tag does NOT ship one of these
        ///     for the code layer as far as this scaffold found, so
        ///     capturing a fresh trace via a local reference build, the
        ///     same way `kat_vectors_code.zig`'s encode vectors were
        ///     obtained, is the way to get one).
        ///
        ///  2. **Error-locator polynomial sigma(x)** (reference:
        ///     `compute_elp`, a constant-time Berlekamp-Massey variant —
        ///     Lin & Costello ch. 6, "BCH Codes"). Maintains `sigma` and
        ///     an auxiliary `X_sigma_p` (representing `X^(mu-rho) *
        ///     sigma_p(X)`) across `2*delta` iterations, updating both in
        ///     place via masked (branch-free) selects rather than an `if`
        ///     on "did the discrepancy increase the degree" — mirror this
        ///     constant-time structure (masks built from `-(d >> 15)` /
        ///     equivalent, same style as this repo's `gf2x.zig` posture)
        ///     rather than translating it into a branchy from-scratch
        ///     Berlekamp-Massey, since sigma's degree and the discrepancy
        ///     value are functions of the (secret-derived) received
        ///     codeword. Returns `deg_sigma`, sigma's actual degree
        ///     (`<= delta` for a correctable pattern).
        ///
        ///  3. **Root-finding via additive FFT** (reference:
        ///     `compute_roots`, delegating to `fft`/`fft_retrieve_error_poly`
        ///     in `src/common/fft.c`). **This is the hardest sub-step**:
        ///     the reference does NOT use Chien search (the textbook
        ///     "test every field element" approach) — it uses an
        ///     *additive* FFT (Gao & Mateer, "Additive Fast Fourier
        ///     Transforms over Finite Fields", IEEE Trans. Info. Theory
        ///     56 (2010), with the radix/subset-sum optimizations from
        ///     Bernstein/Chou/Schwabe, "mcbits") to evaluate `sigma` at
        ///     ALL 256 field elements in `O(m 2^m)` instead of `O(delta *
        ///     2^m)` field multiplies. The structure (from `fft.c`,
        ///     already fetched into this scaffold's provenance trail —
        ///     see NOTICE): `compute_fft_betas` (the basis `2^(m-1-i)` for
        ///     `i` in `[0, m-1)`, m=8), `compute_subset_sums` (all `2^k`
        ///     XOR-subset-sums of a `k`-element basis), a radix
        ///     conversion `f(x) = f0(x^2-x) + x*f1(x^2-x)` (small-case
        ///     `switch` on `m_f` for m_f in `1..4`, falling back to
        ///     `radix_big` for HQC-192/256's `PARAM_FFT=5`), and a
        ///     recursive `fft_rec` that halves the problem each level.
        ///     `fft_retrieve_error_poly` then maps FFT-evaluation-domain
        ///     indices back to error POSITIONS via
        ///     `PARAM_GF_MUL_ORDER - gf_log[gammas_sums[i]]` (i.e. `255 -
        ///     log(betasum)`, using this module's own `gf256.inverse`-style
        ///     discrete-log arithmetic) and reads the root/non-root
        ///     decision off the sign of each evaluation (`w[i] == 0`
        ///     tested via `(-w[i]) >> 15`, a constant-time zero-test, not
        ///     `w[i] == 0`). Output: an `error: [256]u8` indicator array
        ///     (nonzero at each error position). **Do not substitute
        ///     Chien search** — the doc-contract explicitly calls for
        ///     matching the reference's additive-FFT algorithm because
        ///     Part 3 needs this decoder's *timing shape* (not just
        ///     final correctness) to plausibly match a real HQC
        ///     implementation, and because Chien search is `O(n1 * delta)`
        ///     field operations per decode vs. the FFT's `O(m * 2^m)` —
        ///     different enough to matter if this code is ever used past
        ///     KAT reproduction.
        ///
        ///     (SPEC.md's older "Arc plan" note about shortened-RS
        ///     `alpha_ij_pow` index offsets of 209/199/165 was written
        ///     before this scaffold pass actually fetched and read the
        ///     v5.0.0 reference source, and does not match what's
        ///     actually there — v5.0.0's `alpha_ij_pow` tables and additive
        ///     FFT have no such offset constants. That note should be
        ///     treated as superseded by this doc comment, not as
        ///     additional truth to reconcile.)
        ///
        ///  4. **Error-evaluator polynomial z(x)** (reference:
        ///     `compute_z_poly`, Lin & Costello ch. 6). `z[0] = 1`;
        ///     `z[i] = sigma[i]` for `i <= deg_sigma` (masked to 0 beyond
        ///     that degree); then folds in the syndromes:
        ///     `z[1] ^= S_0`, and for `i` in `[2, delta]`,
        ///     `z[i] ^= S_{i-1} XOR-sum_{j=1}^{i-1} sigma[j]*S_{i-j-1}`
        ///     (again masked to only apply within `deg_sigma`'s range).
        ///
        ///  5. **Error values via Forney's formula** (reference:
        ///     `compute_error_values`, Lin & Costello's `beta_j`/`e_j`
        ///     construction, "page 31 of the documentation" per the
        ///     reference's own comment — i.e. the HQC spec PDF, not this
        ///     scaffold). For each detected error position `i` (from
        ///     step 3's indicator array, processed in a fixed
        ///     `delta`-slot constant-access pattern via a running
        ///     `delta_counter`, NOT a variable-length list), compute
        ///     `beta_j = alpha^i` (the error LOCATOR), then the error
        ///     VALUE via `e_j = (sum_j inverse(beta_j)^j * z[j]) *
        ///     inverse(product_{k != j} (1 + inverse(beta_j)*beta_k))`ish
        ///     — port `compute_error_values`'s exact loop structure
        ///     (including its masked "is this slot actually a found
        ///     error, i < delta_real_value" gating) rather than
        ///     re-deriving Forney's formula from a textbook, since the
        ///     reference's specific constant-time bookkeeping (which slot
        ///     holds which error) is easy to get subtly wrong from a
        ///     from-scratch derivation.
        ///
        ///  6. **Correct and extract** (reference: `correct_errors` +
        ///     the final `memcpy`). XOR `error_values` into `cdw`
        ///     positionally, then return the LAST `k` bytes (positions
        ///     `[redundancy, n1)` — the message-suffix half of the
        ///     systematic layout `encode` produces, i.e. `cdw[redundancy..]`
        ///     post-correction, NOT `cdw[PARAM_G-1..]` as the reference's
        ///     C literally writes it — `PARAM_G - 1 == redundancy` always
        ///     holds, see `RS`'s own `comptime` assert above, so these are
        ///     the same slice; spelled out here to avoid `PARAM_G` being
        ///     mistaken for an unrelated constant this module doesn't
        ///     define).
        ///
        /// **KAT coverage** (see `code_kat_test.zig`): `decode(encode(m))
        /// == m` for many random `m` (zero-error case exercises steps 1-6
        /// with an all-zero error pattern — sigma comes out degree 0);
        /// `decode(encode(m) with <= delta symbol errors XORed in) == m`
        /// for weight-`<= delta` error patterns (the actual
        /// error-correction property). Beyond-capacity behavior (`> delta`
        /// errors): like the reference, there is NO failure/rejection
        /// signal in this layer — sigma's degree bookkeeping saturates and
        /// the correction pass simply produces a wrong message (silent
        /// miscorrection), which HQC's FO transform detects one layer up
        /// via re-encryption, not here.
        pub fn decode(cdw: Codeword) Message {
            var cdw_bytes: Codeword = cdw;

            // Step 1: syndromes.
            var syndromes: [2 * delta]u16 = [_]u16{0} ** (2 * delta);
            computeSyndromes(&syndromes, &cdw_bytes);

            // Step 2: error-locator polynomial sigma(x), constant-time
            // Berlekamp-Massey. Sigma's degree is at most delta but the
            // additive FFT requires the buffer padded to 2^param_fft.
            var sigma: [fft_len]u16 = [_]u16{0} ** fft_len;
            const deg = computeElp(&sigma, &syndromes);

            // Step 3: root-finding via the Gao-Mateer additive FFT ->
            // per-position error indicator array.
            var err: [1 << param_m]u8 = [_]u8{0} ** (1 << param_m);
            computeRoots(&err, &sigma);

            // Step 4: error-evaluator polynomial z(x).
            var z: [delta + 1]u16 = [_]u16{0} ** (delta + 1);
            computeZPoly(&z, &sigma, deg, &syndromes);

            // Step 5: error values via Forney's formula (the reference's
            // constant-access-pattern beta_j/e_j bookkeeping).
            var error_values: [n1]u16 = [_]u16{0} ** n1;
            computeErrorValues(&error_values, &z, &err);

            // Step 6: correct and extract the systematic message suffix.
            for (0..n1) |i| cdw_bytes[i] ^= @as(u8, @truncate(error_values[i]));
            return cdw_bytes[redundancy..].*;
        }

        // ── decode internals (ports of reed_solomon.c + fft.c) ─────────

        /// GF(2^8) extension degree (reference: `PARAM_M`).
        const param_m = 8;
        /// |GF(2^8)*| = 255 (reference: `PARAM_GF_MUL_ORDER`).
        const gf_mul_order = 255;
        /// log2 of the FFT input-buffer size: the smallest power of two
        /// holding sigma's `delta + 1` coefficients (reference:
        /// `PARAM_FFT` — 4 for hqc-128, 5 for hqc-192/256, confirmed
        /// against each parameter set's `parameters.h`).
        const param_fft = blk: {
            var f = 1;
            while ((1 << f) < delta + 1) f += 1;
            break :blk f;
        };
        const fft_len = 1 << param_fft;
        comptime {
            std.debug.assert(fft_len >= delta + 1);
            // Reference values: hqc-128 -> 4, hqc-192/256 -> 5.
            std.debug.assert(param_fft == (if (delta == 15) 4 else 5));
        }

        /// `gf.mul` on u16-held GF(2^8) values (every value in this
        /// decoder is < 256 by construction; u16 storage mirrors the
        /// reference's `uint16_t` arithmetic/masking width).
        inline fn gmul(a: u16, b: u16) u16 {
            return gf.mul(@intCast(a), @intCast(b));
        }

        inline fn ginv(a: u16) u16 {
            return gf.inverse(@intCast(a));
        }

        inline fn gsquare(a: u16) u16 {
            return gf.square(@intCast(a));
        }

        /// 0xffff iff `x != 0`, branch-free (equivalent to the reference's
        /// `-((int32_t)x) >> 31` arithmetic-shift trick; valid here since
        /// every masked quantity is < 2^15).
        inline fn maskNonzero(x: u16) u16 {
            return 0 -% ((x | (0 -% x)) >> 15);
        }

        /// Step 1 (reference: `compute_syndromes`): S_i = cdw[0] XOR
        /// XOR-sum_{j=1}^{n1-1} cdw[j] * alpha^((i+1)*j). The reference
        /// reads alpha^((i+1)*j) from its precomputed `alpha_ij_pow[i][j-1]`
        /// table (verified: row i, column j-1 holds exp[((i+1)*j) % 255]);
        /// computing the exponent directly from `gf.exp` is byte-identical
        /// and the exponent arithmetic involves only PUBLIC loop indices.
        fn computeSyndromes(syndromes: *[2 * delta]u16, cdw: *const Codeword) void {
            for (0..2 * delta) |i| {
                for (1..n1) |j| {
                    const alpha_ij: u8 = @intCast(gf.exp[((i + 1) * j) % gf_mul_order]);
                    syndromes[i] ^= gf.mul(cdw[j], alpha_ij);
                }
                syndromes[i] ^= cdw[0];
            }
        }

        /// Step 2 (reference: `compute_elp`): constant-time
        /// Berlekamp-Massey. All state updates (rho, d_p, X_sigma_p, the
        /// degree bookkeeping) are masked selects — mask12 = "the degree
        /// increased this iteration" — never branches on the
        /// secret-derived discrepancy `d`. `pp` (= 2*rho in the
        /// reference's naming) starts at 0xffff (-1) and all arithmetic
        /// on it is deliberately wrapping u16, exactly as the C's
        /// unsigned arithmetic behaves. Returns deg(sigma).
        fn computeElp(sigma: *[fft_len]u16, syndromes: *const [2 * delta]u16) u16 {
            var deg_sigma: u16 = 0;
            var deg_sigma_p: u16 = 0;
            var deg_sigma_copy: u16 = 0;
            var sigma_copy: [delta + 1]u16 = [_]u16{0} ** (delta + 1);
            var x_sigma_p: [delta + 1]u16 = [_]u16{0} ** (delta + 1);
            x_sigma_p[1] = 1;
            var pp: u16 = 0xffff; // 2*rho
            var d_p: u16 = 1;
            var d: u16 = syndromes[0];

            sigma[0] = 1;
            var mu: u16 = 0;
            while (mu < 2 * delta) : (mu += 1) {
                // Save sigma in case we need it to update X_sigma_p
                // (reference copies exactly delta coefficients).
                @memcpy(sigma_copy[0..delta], sigma[0..delta]);
                deg_sigma_copy = deg_sigma;

                const dd = gmul(d, ginv(d_p));

                {
                    var i: usize = 1;
                    while (i <= mu + 1 and i <= delta) : (i += 1) {
                        sigma[i] ^= gmul(dd, x_sigma_p[i]);
                    }
                }

                const deg_x = mu -% pp;
                const deg_x_sigma_p = deg_x +% deg_sigma_p;

                // mask1 = 0xffff iff d != 0
                const mask1: u16 = 0 -% ((0 -% d) >> 15);
                // mask2 = 0xffff iff deg_x_sigma_p > deg_sigma
                const mask2: u16 = 0 -% ((deg_sigma -% deg_x_sigma_p) >> 15);
                // mask12 = 0xffff iff deg_sigma increased
                const mask12 = mask1 & mask2;
                deg_sigma ^= mask12 & (deg_x_sigma_p ^ deg_sigma);

                if (mu == 2 * delta - 1) break;

                pp ^= mask12 & (mu ^ pp);
                d_p ^= mask12 & (d ^ d_p);
                {
                    var i: usize = delta;
                    while (i > 0) : (i -= 1) {
                        x_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^ (~mask12 & x_sigma_p[i - 1]);
                    }
                }

                deg_sigma_p ^= mask12 & (deg_sigma_copy ^ deg_sigma_p);
                d = syndromes[mu + 1];

                {
                    var i: usize = 1;
                    while (i <= mu + 1 and i <= delta) : (i += 1) {
                        d ^= gmul(sigma[i], syndromes[mu + 1 - i]);
                    }
                }
            }

            return deg_sigma;
        }

        /// Step 3 (reference: `compute_roots` -> `fft` +
        /// `fft_retrieve_error_poly`): evaluate sigma at all 256 field
        /// elements via the Gao-Mateer additive FFT and mark each error
        /// POSITION in the indicator array. `sigma` is not modified (the
        /// FFT twists only its own internal half-buffers), so it stays
        /// valid for step 4.
        fn computeRoots(err: *[1 << param_m]u8, sigma: *const [fft_len]u16) void {
            var w: [1 << param_m]u16 = [_]u16{0} ** (1 << param_m);
            fftMain(&w, sigma, delta + 1);
            fftRetrieveErrorPoly(err, &w);
        }

        /// The additive-FFT basis omitting the final element 1
        /// (reference: `compute_fft_betas`): {2^7, 2^6, ..., 2^1}.
        fn computeFftBetas(betas: *[param_m - 1]u16) void {
            for (0..param_m - 1) |i| {
                betas[i] = @as(u16, 1) << @intCast(param_m - 1 - i);
            }
        }

        /// All 2^|set| XOR-subset-sums of `set`; entry i is the sum of
        /// the elements selected by i's binary form (reference:
        /// `compute_subset_sums`).
        fn computeSubsetSums(subset_sums: []u16, set: []const u16) void {
            subset_sums[0] = 0;
            for (set, 0..) |elt, i| {
                const half = @as(usize, 1) << @intCast(i);
                for (0..half) |j| {
                    subset_sums[half + j] = elt ^ subset_sums[j];
                }
            }
        }

        /// Radix conversion f(x) = f0(x^2-x) + x*f1(x^2-x) (reference:
        /// `radix` — Bernstein/Chou/Schwabe's unrolled small cases,
        /// falling through to the recursive `radix_big` for m_f > 4,
        /// which only hqc-192/256's param_fft = 5 top-level call reaches).
        fn radixConv(f0: []u16, f1: []u16, f: []const u16, m_f: usize) void {
            switch (m_f) {
                4 => {
                    f0[4] = f[8] ^ f[12];
                    f0[6] = f[12] ^ f[14];
                    f0[7] = f[14] ^ f[15];
                    f1[5] = f[11] ^ f[13];
                    f1[6] = f[13] ^ f[14];
                    f1[7] = f[15];
                    f0[5] = f[10] ^ f[12] ^ f1[5];
                    f1[4] = f[9] ^ f[13] ^ f0[5];

                    f0[0] = f[0];
                    f1[3] = f[7] ^ f[11] ^ f[15];
                    f0[3] = f[6] ^ f[10] ^ f[14] ^ f1[3];
                    f0[2] = f[4] ^ f0[4] ^ f0[3] ^ f1[3];
                    f1[1] = f[3] ^ f[5] ^ f[9] ^ f[13] ^ f1[3];
                    f1[2] = f[3] ^ f1[1] ^ f0[3];
                    f0[1] = f[2] ^ f0[2] ^ f1[1];
                    f1[0] = f[1] ^ f0[1];
                },
                3 => {
                    f0[0] = f[0];
                    f0[2] = f[4] ^ f[6];
                    f0[3] = f[6] ^ f[7];
                    f1[1] = f[3] ^ f[5] ^ f[7];
                    f1[2] = f[5] ^ f[6];
                    f1[3] = f[7];
                    f0[1] = f[2] ^ f0[2] ^ f1[1];
                    f1[0] = f[1] ^ f0[1];
                },
                2 => {
                    f0[0] = f[0];
                    f0[1] = f[2] ^ f[3];
                    f1[0] = f[1] ^ f0[1];
                    f1[1] = f[3];
                },
                1 => {
                    f0[0] = f[0];
                    f1[0] = f[1];
                },
                else => radixBig(f0, f1, f, m_f),
            }
        }

        /// Generalized radix step for 2^m_f-coefficient polynomials
        /// beyond the unrolled cases (reference: `radix_big`). Only ever
        /// entered with m_f == 5 (hqc-192/256), recursing into the
        /// unrolled m_f == 4 case.
        fn radixBig(f0: []u16, f1: []u16, f: []const u16, m_f: usize) void {
            // Buffer sizes follow the reference's worst-case declarations
            // (2*(2^(param_fft-2))+1 / 2^(param_fft-2)).
            var q: [2 * (1 << (param_fft - 2)) + 1]u16 = [_]u16{0} ** (2 * (1 << (param_fft - 2)) + 1);
            var r: [2 * (1 << (param_fft - 2)) + 1]u16 = [_]u16{0} ** (2 * (1 << (param_fft - 2)) + 1);
            var q0: [1 << (param_fft - 2)]u16 = [_]u16{0} ** (1 << (param_fft - 2));
            var q1: [1 << (param_fft - 2)]u16 = [_]u16{0} ** (1 << (param_fft - 2));
            var r0: [1 << (param_fft - 2)]u16 = [_]u16{0} ** (1 << (param_fft - 2));
            var r1: [1 << (param_fft - 2)]u16 = [_]u16{0} ** (1 << (param_fft - 2));

            const n = @as(usize, 1) << @intCast(m_f - 2);
            @memcpy(q[0..n], f[3 * n .. 4 * n]);
            @memcpy(q[n .. 2 * n], f[3 * n .. 4 * n]);
            @memcpy(r[0 .. 2 * n], f[0 .. 2 * n]);

            for (0..n) |i| {
                q[i] ^= f[2 * n + i];
                r[n + i] ^= q[i];
            }

            radixConv(&q0, &q1, q[0 .. 2 * n], m_f - 1);
            radixConv(&r0, &r1, r[0 .. 2 * n], m_f - 1);

            @memcpy(f0[0..n], r0[0..n]);
            @memcpy(f0[n .. 2 * n], q0[0..n]);
            @memcpy(f1[0..n], r1[0..n]);
            @memcpy(f1[n .. 2 * n], q1[0..n]);
        }

        /// Recursive additive-FFT core (reference: `fft_rec`): evaluates
        /// f (2^m_f coefficients, f_coeffs of them meaningful) at all
        /// subset sums of the m-element basis `betas` into w[0..2^m].
        /// `f` is twisted in place at each level (it is always one of the
        /// caller's own half-buffers, never the original sigma).
        fn fftRec(w: []u16, f: []u16, f_coeffs: usize, m: usize, m_f: usize, betas: []const u16) void {
            var f0_buf: [1 << (param_fft - 2)]u16 = [_]u16{0} ** (1 << (param_fft - 2));
            var f1_buf: [1 << (param_fft - 2)]u16 = [_]u16{0} ** (1 << (param_fft - 2));
            var gammas: [param_m - 2]u16 = [_]u16{0} ** (param_m - 2);
            var deltas: [param_m - 2]u16 = [_]u16{0} ** (param_m - 2);
            var gammas_sums: [1 << (param_m - 2)]u16 = [_]u16{0} ** (1 << (param_m - 2));
            var u_buf: [1 << (param_m - 2)]u16 = [_]u16{0} ** (1 << (param_m - 2));
            var v_buf: [1 << (param_m - 2)]u16 = [_]u16{0} ** (1 << (param_m - 2));
            // At the recursion floor m always equals param_m-(param_fft-1)
            // (m and m_f decrement in lockstep from param_m-1/param_fft-1).
            var tmp: [param_m - (param_fft - 1)]u16 = [_]u16{0} ** (param_m - (param_fft - 1));

            // Step 1: base case — f is linear, evaluate directly by
            // doubling over the basis.
            if (m_f == 1) {
                for (0..m) |i| {
                    tmp[i] = gmul(betas[i], f[1]);
                }
                w[0] = f[0];
                var x: usize = 1;
                for (0..m) |j| {
                    for (0..x) |idx| {
                        w[x + idx] = w[idx] ^ tmp[j];
                    }
                    x <<= 1;
                }
                return;
            }

            // Step 2: twist f so the last basis element becomes 1.
            if (betas[m - 1] != 1) {
                var beta_m_pow: u16 = 1;
                const x = @as(usize, 1) << @intCast(m_f);
                for (1..x) |i| {
                    beta_m_pow = gmul(beta_m_pow, betas[m - 1]);
                    f[i] = gmul(beta_m_pow, f[i]);
                }
            }

            // Step 3: radix conversion.
            radixConv(&f0_buf, &f1_buf, f, m_f);

            // Step 4: gammas (scaled basis) and deltas (next level's basis).
            for (0..m - 1) |i| {
                gammas[i] = gmul(betas[i], ginv(betas[m - 1]));
                deltas[i] = gsquare(gammas[i]) ^ gammas[i];
            }
            computeSubsetSums(gammas_sums[0 .. @as(usize, 1) << @intCast(m - 1)], gammas[0 .. m - 1]);

            // Step 5: recurse on f0.
            fftRec(&u_buf, &f0_buf, (f_coeffs + 1) / 2, m - 1, m_f - 1, deltas[0 .. m - 1]);

            const half = @as(usize, 1) << @intCast(m - 1);
            if (f_coeffs <= 3) {
                // 3-coefficient polynomial f case: f1 is constant.
                w[0] = u_buf[0];
                w[half] = u_buf[0] ^ f1_buf[0];
                for (1..half) |i| {
                    w[i] = u_buf[i] ^ gmul(gammas_sums[i], f1_buf[0]);
                    w[half + i] = w[i] ^ f1_buf[0];
                }
            } else {
                fftRec(&v_buf, &f1_buf, f_coeffs / 2, m - 1, m_f - 1, deltas[0 .. m - 1]);

                // Step 6: butterfly combine.
                @memcpy(w[half .. 2 * half], v_buf[0..half]);
                w[0] = u_buf[0];
                w[half] ^= u_buf[0];
                for (1..half) |i| {
                    w[i] = u_buf[i] ^ gmul(gammas_sums[i], v_buf[i]);
                    w[half + i] ^= w[i];
                }
            }
        }

        /// Top-level additive FFT (reference: `fft`): evaluates sigma at
        /// every GF(2^8) element into w[0..256]. The top level's basis
        /// ends with 1 (beta_m = 1), so there is no twist here; `f`
        /// itself is only READ (radixConv copies into local halves).
        fn fftMain(w: *[1 << param_m]u16, f: *const [fft_len]u16, f_coeffs: usize) void {
            var betas: [param_m - 1]u16 = [_]u16{0} ** (param_m - 1);
            var betas_sums: [1 << (param_m - 1)]u16 = [_]u16{0} ** (1 << (param_m - 1));
            var f0: [1 << (param_fft - 1)]u16 = [_]u16{0} ** (1 << (param_fft - 1));
            var f1: [1 << (param_fft - 1)]u16 = [_]u16{0} ** (1 << (param_fft - 1));
            var deltas: [param_m - 1]u16 = [_]u16{0} ** (param_m - 1);
            var u: [1 << (param_m - 1)]u16 = [_]u16{0} ** (1 << (param_m - 1));
            var v: [1 << (param_m - 1)]u16 = [_]u16{0} ** (1 << (param_m - 1));

            computeFftBetas(&betas);
            computeSubsetSums(&betas_sums, &betas);

            radixConv(&f0, &f1, f, param_fft);

            for (0..param_m - 1) |i| {
                deltas[i] = gsquare(betas[i]) ^ betas[i];
            }

            fftRec(&u, &f0, (f_coeffs + 1) / 2, param_m - 1, param_fft - 1, &deltas);
            fftRec(&v, &f1, f_coeffs / 2, param_m - 1, param_fft - 1, &deltas);

            const half = @as(usize, 1) << (param_m - 1);
            @memcpy(w[half .. 2 * half], v[0..half]);
            w[0] = u[0];
            w[half] ^= u[0];
            for (1..half) |i| {
                w[i] = u[i] ^ gmul(betas_sums[i], v[i]);
                w[half + i] ^= w[i];
            }
        }

        /// Map the FFT's evaluation array back to error POSITIONS
        /// (reference: `fft_retrieve_error_poly`): evaluation index i
        /// corresponds to field element betas_sums[i] (even elements) or
        /// betas_sums[i]^1 (odd, via w's upper half); a root r of sigma
        /// marks error position 255 - log(r) (the root is the LOCATOR's
        /// inverse). Element 0 (never a root, sigma[0]=1) and element 1
        /// (position 0, since 255 - log(1) wraps 255 -> 0) both fold into
        /// error[0], exactly as the reference special-cases them. The
        /// zero-test is the same branch-free `(0 - w) >> 15` the
        /// reference uses.
        fn fftRetrieveErrorPoly(err: *[1 << param_m]u8, w: *const [1 << param_m]u16) void {
            var gammas: [param_m - 1]u16 = [_]u16{0} ** (param_m - 1);
            var gammas_sums: [1 << (param_m - 1)]u16 = [_]u16{0} ** (1 << (param_m - 1));

            computeFftBetas(&gammas);
            computeSubsetSums(&gammas_sums, &gammas);

            const half = @as(usize, 1) << (param_m - 1);
            err[0] ^= @intCast(1 ^ ((0 -% w[0]) >> 15));
            err[0] ^= @intCast(1 ^ ((0 -% w[half]) >> 15));

            for (1..half) |i| {
                var index: usize = gf_mul_order - gf.log[gammas_sums[i]];
                err[index] ^= @intCast(1 ^ ((0 -% w[i]) >> 15));

                index = gf_mul_order - gf.log[gammas_sums[i] ^ 1];
                err[index] ^= @intCast(1 ^ ((0 -% w[half + i]) >> 15));
            }
        }

        /// Step 4 (reference: `compute_z_poly`): z[0] = 1, z[i] =
        /// sigma[i] masked to i <= deg(sigma), then fold in the
        /// syndromes; every coefficient update is masked by the same
        /// branch-free "i <= degree" select the reference uses.
        fn computeZPoly(z: *[delta + 1]u16, sigma: *const [fft_len]u16, degree: u16, syndromes: *const [2 * delta]u16) void {
            z[0] = 1;

            for (1..delta + 1) |i| {
                // mask = 0xffff iff i <= degree
                const mask: u16 = 0 -% ((@as(u16, @intCast(i)) -% degree -% 1) >> 15);
                z[i] = mask & sigma[i];
            }

            z[1] ^= syndromes[0];

            for (2..delta + 1) |i| {
                const mask: u16 = 0 -% ((@as(u16, @intCast(i)) -% degree -% 1) >> 15);
                z[i] ^= mask & syndromes[i - 1];

                for (1..i) |j| {
                    z[i] ^= mask & gmul(sigma[j], syndromes[i - j - 1]);
                }
            }
        }

        /// Step 5 (reference: `compute_error_values`): Forney. First
        /// gather the error LOCATORS beta_j = alpha^i for each flagged
        /// position i into a fixed delta-slot array via the reference's
        /// constant-access-pattern delta_counter walk (every position and
        /// every slot is touched every iteration; masks select the one
        /// real write). Then each error VALUE e_j = z(beta_j^-1) /
        /// prod_{k != j}(1 + beta_j^-1 * beta_k), masked to the
        /// actually-found error count. Finally scatter e_j back to
        /// positions with the same constant-access walk.
        fn computeErrorValues(error_values: *[n1]u16, z: *const [delta + 1]u16, err: *const [1 << param_m]u8) void {
            var beta_j: [delta]u16 = [_]u16{0} ** delta;
            var e_j: [delta]u16 = [_]u16{0} ** delta;

            // Compute the beta_{j_i} (locators of the flagged positions).
            var delta_counter: u16 = 0;
            for (0..n1) |i| {
                var found: u16 = 0;
                const mask1 = maskNonzero(err[i]); // err[i] != 0
                for (0..delta) |j| {
                    // mask2 = 0xffff iff j == delta_counter
                    const mask2 = ~maskNonzero(@as(u16, @intCast(j)) ^ delta_counter);
                    beta_j[j] +%= mask1 & mask2 & @as(u16, @intCast(gf.exp[i]));
                    found +%= mask1 & mask2 & 1;
                }
                delta_counter += found;
            }
            const delta_real_value = delta_counter;

            // Compute the e_{j_i} (error values, Forney's formula).
            for (0..delta) |i| {
                var tmp1: u16 = 1;
                var tmp2: u16 = 1;
                const inverse = ginv(beta_j[i]);
                var inverse_power_j: u16 = 1;

                for (1..delta + 1) |j| {
                    inverse_power_j = gmul(inverse_power_j, inverse);
                    tmp1 ^= gmul(inverse_power_j, z[j]);
                }
                for (1..delta) |kk| {
                    tmp2 = gmul(tmp2, 1 ^ gmul(inverse, beta_j[(i + kk) % delta]));
                }
                // mask1 = 0xffff iff i < delta_real_value (the reference's
                // arithmetic-shift `((int16_t)i - delta_real_value) >> 15`)
                const mask1: u16 = 0 -% @as(u16, @intFromBool(i < delta_real_value));
                e_j[i] = mask1 & gmul(tmp1, ginv(tmp2));
            }

            // Place the e_{j_i} at the right coordinates of the output.
            delta_counter = 0;
            for (0..n1) |i| {
                var found: u16 = 0;
                const mask1 = maskNonzero(err[i]); // err[i] != 0
                for (0..delta) |j| {
                    const mask2 = ~maskNonzero(@as(u16, @intCast(j)) ^ delta_counter);
                    error_values[i] +%= mask1 & mask2 & e_j[j];
                    found +%= mask1 & mask2 & 1;
                }
                delta_counter += found;
            }
        }
    };
}

// ── tests: encode only (decode is gated, see code_kat_test.zig) ────────

const RS128 = RS(params.hqc128, generator_hqc128);
const RS192 = RS(params.hqc192, generator_hqc192);
const RS256 = RS(params.hqc256, generator_hqc256);

test "RS: redundancy == 2*delta for every parameter set" {
    const t = std.testing;
    try t.expectEqual(@as(usize, 30), RS128.redundancy);
    try t.expectEqual(@as(usize, 32), RS192.redundancy);
    try t.expectEqual(@as(usize, 58), RS256.redundancy);
}

test "RS128: encode of the all-zero message is the all-zero codeword" {
    const t = std.testing;
    const msg: RS128.Message = [_]u8{0} ** RS128.k;
    const cdw = RS128.encode(msg);
    try t.expectEqualSlices(u8, &([_]u8{0} ** RS128.n1), &cdw);
}

test "RS128: encode is systematic (message bytes reappear verbatim as the codeword's tail)" {
    const t = std.testing;
    var msg: RS128.Message = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast(i);
    const cdw = RS128.encode(msg);
    try t.expectEqualSlices(u8, &msg, cdw[RS128.redundancy..]);
}
