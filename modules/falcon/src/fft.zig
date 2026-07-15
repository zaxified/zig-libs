// SPDX-License-Identifier: MIT
//! fft — floating-point FFT over the real polynomial ring R[x]/(x^n+1)
//! (n = 2^logn), the transform Falcon's trapdoor sampler (`ffsampling`)
//! runs its LDL* tree construction and nearest-plane recursion in. This
//! is a DIFFERENT transform from `poly.zig`'s exact integer NTT over
//! Z_q[x]/(x^n+1) — that one is complete, exact, and reused everywhere
//! verification needs it; this one is net-new (nothing in this module
//! does floating-point arithmetic today) and exists only for the signer.
//!
//! Falcon spec §3.4 (Algorithms 1/2 `FFT`/`iFFT`). A negacyclic
//! real-coefficient FFT of degree n embeds into a complex FFT of degree
//! n/2 (each output bin holds one pair of conjugate-symmetric roots); the
//! reference implementation's `fft.c` — which this is modeled after in
//! shape only, not ported — uses an iterative split-radix schedule with a
//! comptime-generated twiddle table, structurally the same idea as
//! `poly.zig`'s NTT (`zetas[]`, bit-reversed traversal) but over `f64`
//! complex numbers instead of exact Z_q arithmetic.
//!
//! `splitFft`/`mergeFft` (spec §3.8.3 Algorithms 7/8), the two operations
//! `ffsampling.zig`'s LDL* tree recursion needs on top of plain fft/ifft,
//! live in `ffsampling.zig` instead of here: unlike this file's `fft`/
//! `ifft` (fixed at `Ring`'s top-level degree n), they recurse over
//! SHRINKING degrees at each tree level, so they naturally take a
//! runtime degree parameter rather than being tied to a single comptime
//! `Ring`.
//!
//! Floating-point-adjacent bugs here are one of the ways a subtly wrong
//! signer leaks the secret key without any individual signature failing
//! to verify — see `gaussian.zig`'s SamplerZ note for the sharper version
//! of that warning.

const std = @import("std");

/// FFT/iFFT over a `poly.Ring(logn)` instantiation's degree n. Generic
/// the same way `poly.Ring`/`codec.Codec` are, so it serves both
/// Falcon-512 and Falcon-1024 from one implementation once written.
pub fn Fft(comptime Ring: type) type {
    return struct {
        const Self = @This();

        pub const n = Ring.n;
        /// Number of complex bins representing one degree-n real
        /// polynomial in the FFT domain (conjugate symmetry halves it).
        pub const hn = n / 2;

        pub const Complex = struct { re: f64, im: f64 };
        /// A degree-n real polynomial's FFT-domain representation.
        pub const FftPoly = [hn]Complex;

        /// Forward FFT: real coefficients -> FFT domain (spec §3.4
        /// Algorithm 1).
        pub fn fft(a: *const [n]f64, out: *FftPoly) void {
            _ = a;
            _ = out;
            @panic("TODO(fable/core): Falcon FFT (spec §3.4 Algorithm 1) — degree-" ++
                std.fmt.comptimePrint("{d}", .{n}) ++
                " negacyclic real FFT, split-radix over f64 complex pairs, " ++
                "twiddles = primitive 2n-th roots of unity in C (comptime table, " ++
                "same shape as poly.zig's NTT zetas[] but over C instead of Z_q). " ++
                "Needed by ffsampling.zig's LDL* tree build + nearest-plane " ++
                "sampling; nothing else in this module does floating-point math.");
        }

        /// Inverse FFT: FFT domain -> real coefficients (spec §3.4
        /// Algorithm 2), the exact inverse of `fft` above.
        pub fn ifft(a: *const FftPoly, out: *[n]f64) void {
            _ = a;
            _ = out;
            @panic("TODO(fable/core): Falcon iFFT (spec §3.4 Algorithm 2) — inverse " ++
                "of fft.zig's `fft` above; same twiddle table, reverse schedule.");
        }
    };
}

test "Fft(Ring) instantiates for both parameter sets without evaluating the stubs" {
    const poly = @import("poly.zig");
    // Merely instantiating the generic type and reading its comptime
    // constants must not call the stub functions (those only panic when
    // INVOKED, not at instantiation) — this pins that down for both
    // degrees so a future refactor can't accidentally make the panic
    // comptime-eager.
    try std.testing.expectEqual(@as(usize, 256), Fft(poly.Ring512).hn);
    try std.testing.expectEqual(@as(usize, 512), Fft(poly.Ring1024).hn);
}
