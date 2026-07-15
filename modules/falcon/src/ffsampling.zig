// SPDX-License-Identifier: MIT
//! ffsampling — the Falcon/FN-DSA trapdoor sampler: builds the LDL*
//! decomposition tree of the secret NTRU basis over the FFT embedding
//! (`buildTree`, spec §3.8.3 Algorithm 9 `ffLDL`) and walks it via the
//! fast-Fourier nearest-plane recursion (`sampleSignature`, spec §3.9.1
//! Algorithm 11 `ffSampling`) to draw a short vector (s1, s2) close to
//! the hashed target point `c` — the heart of Falcon signing.
//!
//! Both functions below are stubs: together with `gaussian.samplerZ`
//! (which every leaf of `sampleSignature`'s recursion calls), this is
//! the hardest and most side-channel-sensitive part of the scheme. An
//! incorrect-but-plausible implementation here has the specific,
//! dangerous failure mode the spec and `root.zig`'s module doc comment
//! both call out: it can still produce signatures that PASS
//! `root.zig`'s verification while statistically leaking the secret
//! basis over many signatures — "the signatures verify" is necessary but
//! nowhere near sufficient evidence of correctness for this file.
//!
//! `splitFft`/`mergeFft` (spec §3.8.3 Algorithms 7/8) live here rather
//! than in `fft.zig`: unlike that file's `fft`/`ifft` (fixed at one
//! comptime `Ring` degree), the LDL* recursion below calls them at every
//! tree level with a SHRINKING degree, so they take a runtime `logn`
//! parameter over slices instead of a comptime-fixed array size.

const std = @import("std");
const fft = @import("fft.zig");
const gaussian = @import("gaussian.zig");

/// The LDL* tree over the FFT embedding: a complete binary tree of depth
/// `Ring.logn`, the shape `buildTree`/Algorithm 9 constructs and
/// `sampleSignature`/Algorithm 11 walks.
///
/// STRUCTURAL PLACEHOLDER: this field layout is a reasonable guess at
/// the eventual shape (flat storage sized like the reference
/// implementation's packed `[]fpr` tree encoding), not a verified
/// layout — nothing outside `buildTree`/`sampleSignature` reads or
/// writes real values through it yet, so whoever implements those two
/// functions should feel free to redefine this type entirely rather than
/// contort a real implementation to fit this guess.
pub fn Tree(comptime Ring: type) type {
    const Complex = fft.Fft(Ring).Complex;
    return struct {
        /// Flat storage for the tree's FFT-domain node data. The
        /// reference implementation packs a depth-logn binary tree of
        /// degree-shrinking FFT rows into (2*logn+1) * (n/2) scalar
        /// slots; mirrored here as Complex slots (this module keeps
        /// FFT-domain data as {re,im} pairs rather than the reference's
        /// interleaved real array).
        nodes: [(2 * Ring.logn + 1) * (Ring.n / 2)]Complex = undefined,
    };
}

/// Split one degree-`n` FFT-domain polynomial (`n = 1 << logn`) into two
/// degree-`n/2` FFT-domain polynomials (spec §3.8.3 Algorithm 7
/// `splitfft`) — one step of the LDL* tree recursion, and also needed
/// on the way back up in `sampleSignature`'s reconstruction.
/// `a.len == n/2`, `f0.len == f1.len == n/4`.
pub fn splitFft(comptime Complex: type, logn: u5, a: []const Complex, f0: []Complex, f1: []Complex) void {
    _ = logn;
    _ = a;
    _ = f0;
    _ = f1;
    @panic("TODO(fable/core): Falcon splitfft (spec §3.8.3 Algorithm 7) — one " ++
        "recursion step of the LDL* tree build/walk. Needs fft.zig's fft/ifft " ++
        "implemented first (this operates on their FFT-domain output).");
}

/// Merge two degree-`n/2` FFT-domain polynomials back into one degree-`n`
/// FFT-domain polynomial (spec §3.8.3 Algorithm 8 `mergefft`) — the
/// inverse of `splitFft`, needed by `sampleSignature`'s bottom-up
/// reconstruction of the sampled short vector.
pub fn mergeFft(comptime Complex: type, logn: u5, f0: []const Complex, f1: []const Complex, out: []Complex) void {
    _ = logn;
    _ = f0;
    _ = f1;
    _ = out;
    @panic("TODO(fable/core): Falcon mergefft (spec §3.8.3 Algorithm 8) — " ++
        "inverse of splitFft above.");
}

/// Build the LDL* tree (spec §3.8.3 Algorithm 9 `ffLDL`) from the secret
/// NTRU basis B = [[g,-f],[G,-F]]: FFT-transform the four polynomials
/// (`fft.Fft(Ring).fft`), form the Gram matrix Gr = B * B^T, and
/// recursively LDL*-decompose it via `splitFft`/`mergeFft` above,
/// bottoming out at degree 1. The result is what `sampleSignature` walks
/// for every signature this key ever produces — `keygen.zig` builds it
/// once per key, not once per signature.
pub fn buildTree(
    comptime Ring: type,
    f: *const [Ring.n]i8,
    g: *const [Ring.n]i8,
    big_f: *const [Ring.n]i8,
    big_g: *const [Ring.n]i8,
) Tree(Ring) {
    _ = f;
    _ = g;
    _ = big_f;
    _ = big_g;
    @panic("TODO(fable/core): ffLDL — Falcon spec §3.8.3 Algorithm 9. Build the " ++
        "LDL* decomposition of the Gram matrix of the secret basis " ++
        "[[g,-f],[G,-F]] over the FFT embedding (fft.zig's fft/ifft to enter the " ++
        "FFT domain, then splitFft/mergeFft above at each recursion level down " ++
        "to degree 1), producing the Tree that sampleSignature below walks. " ++
        "Depends on fft.zig being implemented first.");
}

/// One drawn signature candidate: the short vector (s1, s2), BEFORE the
/// caller's norm-bound check — `sign.zig`'s `signWithRng` does that and
/// resamples (fresh nonce, fresh tree walk) on rejection, mirroring the
/// spec's own outer retry loop.
pub fn SignatureCandidate(comptime Ring: type) type {
    return struct { s1: [Ring.n]i16, s2: [Ring.n]i16 };
}

/// The fast-Fourier nearest-plane recursion (spec §3.9.1 Algorithm 11
/// `ffSampling`), specialized to Falcon signing: computes the FFT-domain
/// target (t0, t1) from the hashed point `c` (`codec.hashToPoint`'s
/// output — REUSED, not reimplemented here) and the public basis
/// relation, samples down `tree` (every leaf draw is one call to
/// `gaussian.samplerZ` — THE side-channel-critical primitive, see
/// gaussian.zig), and reconstructs the short vector (s1, s2) bottom-up
/// via `fft.zig`'s `ifft` / this file's `mergeFft`.
pub fn sampleSignature(
    comptime Ring: type,
    tree: *const Tree(Ring),
    c: *const Ring.Poly,
    rng: std.Random,
) SignatureCandidate(Ring) {
    _ = tree;
    _ = c;
    _ = rng;
    @panic("TODO(fable/core): ffSampling — Falcon spec §3.9.1 Algorithm 11. Walk " ++
        "`tree` top-down computing FFT-domain targets, sampling each leaf via " ++
        "gaussian.samplerZ, then reconstruct the short vector (s1, s2) " ++
        "bottom-up via fft.zig's ifft + this file's mergeFft. Depends on " ++
        "fft.zig, this file's buildTree, and gaussian.zig all being implemented " ++
        "first. `sign.zig`'s signWithRng is the only caller and already handles " ++
        "the accept/reject norm-bound retry loop around this.");
}

test "Tree(Ring) instantiates for both parameter sets without evaluating any stub" {
    const poly = @import("poly.zig");
    // Same instantiation-does-not-panic guarantee as fft.zig/ntru.zig's
    // tests, for the composite type this file adds.
    var t512: Tree(poly.Ring512) = .{};
    var t1024: Tree(poly.Ring1024) = .{};
    _ = &t512;
    _ = &t1024;
}
