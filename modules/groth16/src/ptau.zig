// SPDX-License-Identifier: MIT
//! snarkjs powers-of-tau (`.ptau`, phase 1) — a reader over borrowed bytes.
//!
//! Layout established black-box from snarkjs@0.7.6 output (`tools/snarkjs/
//! gen.sh`; container and encodings in `snarkjs_bin.zig`). For power `p`:
//!
//! | section | contents |
//! |---|---|
//! | 1 | `n8·q · power:u32 · ceremony_power:u32` |
//! | 2 | `[τⁱ]₁`, `i < 2^{p+1} − 1` |
//! | 3 | `[τⁱ]₂`, `i < 2^p` |
//! | 4 | `[ατⁱ]₁`, `i < 2^p` |
//! | 5 | `[βτⁱ]₁`, `i < 2^p` |
//! | 6 | `[β]₂` |
//! | 7 | the contribution chain (not read here) |
//! | 12 | `[Lᵢ(τ)]₁` for every domain `2^0 … 2^{p+1}`, concatenated by level |
//! | 13, 14, 15 | `[Lᵢ(τ)]₂`, `[αLᵢ(τ)]₁`, `[βLᵢ(τ)]₁`, levels `2^0 … 2^p` |
//!
//! Sections 12–15 exist only after `powersoftau prepare phase2`; a raw
//! accumulator is refused (`error.MissingSection`) by the accessors that need
//! them. The Lagrange basis is over this module's own domain (`ω = 5^{(r−1)/n}`,
//! measured: `Σ ωⁱ·Lᵢ(τ) == [τ]₁` on a real file).
//!
//! Points are decoded on demand, so a multi-gigabyte ceremony file costs one
//! pass over the levels a circuit needs, not a decoded copy of all of it.
//! ⚠ The bytes must still be in memory (or mapped) — a positional-read source
//! is a backlog item (SPEC.md).

const std = @import("std");
const bn254 = @import("bn254");
const bin = @import("snarkjs_bin.zig");

const G1 = bn254.G1;
const G2 = bn254.G2;
const ParseError = bin.ParseError;

pub const Ptau = struct {
    file: bin.BinFile,
    power: u5,
    ceremony_power: u32,

    /// Parses the header and checks every section that is present has the
    /// size `power` implies, so the accessors below can slice without
    /// re-checking.
    pub fn parse(bytes: []const u8) ParseError!Ptau {
        const f = try bin.BinFile.parse(bytes, "ptau");
        if (f.version != 1) return error.UnsupportedVersion;
        var hc: bin.Cursor = .{ .bytes = try f.get(1) };
        try bin.expectPrime(&hc, &bin.q_le);
        const power = try hc.int(u32);
        const ceremony_power = try hc.int(u32);
        if (power < 1 or power > 28) return error.BadIndex;
        const p: u5 = @intCast(power);
        const n: u64 = @as(u64, 1) << p;

        // Sizes in u64 through `byteLen`: at power 28 they exceed a 32-bit usize.
        const expect = [_]struct { ty: u32, len: usize, required: bool }{
            .{ .ty = 2, .len = try bin.byteLen(2 * n - 1, bin.g1_bytes), .required = true },
            .{ .ty = 3, .len = try bin.byteLen(n, bin.g2_bytes), .required = true },
            .{ .ty = 4, .len = try bin.byteLen(n, bin.g1_bytes), .required = true },
            .{ .ty = 5, .len = try bin.byteLen(n, bin.g1_bytes), .required = true },
            .{ .ty = 6, .len = bin.g2_bytes, .required = true },
            // Section 12 carries one level more (2^{p+1}) — except at p = 28,
            // where Fr has no 2^29-th root of unity; checked below. ⚠ The
            // p = 28 branch is DERIVED from Fr's 2-adicity, never observed:
            // no recipe run produces such a file. A real one laid out
            // differently is refused (BadSectionSize), never misread.
            .{ .ty = 12, .len = 0, .required = false },
            .{ .ty = 13, .len = try bin.byteLen(2 * n - 1, bin.g2_bytes), .required = false },
            .{ .ty = 14, .len = try bin.byteLen(2 * n - 1, bin.g1_bytes), .required = false },
            .{ .ty = 15, .len = try bin.byteLen(2 * n - 1, bin.g1_bytes), .required = false },
        };
        for (expect) |e| {
            const s = f.sections[e.ty] orelse {
                if (e.required) return error.MissingSection;
                continue;
            };
            if (e.ty == 12) {
                const top: u64 = if (p < 28) 4 * n - 1 else 2 * n - 1;
                if (s.len != try bin.byteLen(top, bin.g1_bytes)) return error.BadSectionSize;
            } else if (s.len != e.len) return error.BadSectionSize;
        }
        return .{ .file = f, .power = p, .ceremony_power = ceremony_power };
    }

    pub const Basis = enum(u32) { tau_g1 = 12, tau_g2 = 13, alpha_tau_g1 = 14, beta_tau_g1 = 15 };

    /// The raw bytes of the Lagrange basis of size `2^level`. `tau_g1` has
    /// levels up to `power + 1`, the others up to `power`.
    pub fn lagrangeBytes(self: Ptau, basis: Basis, level: u5) ParseError![]const u8 {
        const top: u5 = if (basis == .tau_g1 and self.power < 28) self.power + 1 else self.power;
        if (level > top) return error.BadIndex;
        const s = try self.file.get(@intFromEnum(basis));
        const width: usize = if (basis == .tau_g2) bin.g2_bytes else bin.g1_bytes;
        const start = ((@as(usize, 1) << level) - 1) * width;
        return s[start..][0 .. (@as(usize, 1) << level) * width];
    }

    pub fn lagrangeG1(self: Ptau, basis: Basis, level: u5, i: usize) ParseError!G1.Affine {
        std.debug.assert(basis != .tau_g2);
        const s = try self.lagrangeBytes(basis, level);
        if (i >= s.len / bin.g1_bytes) return error.BadIndex;
        return bin.g1FromBytes(s[i * bin.g1_bytes ..][0..bin.g1_bytes]);
    }

    pub fn lagrangeG2(self: Ptau, level: u5, i: usize) ParseError!G2.Affine {
        const s = try self.lagrangeBytes(.tau_g2, level);
        if (i >= s.len / bin.g2_bytes) return error.BadIndex;
        return bin.g2FromBytes(s[i * bin.g2_bytes ..][0..bin.g2_bytes]);
    }

    /// `[τⁱ]₁`, `i < 2^{p+1} − 1`.
    pub fn tauG1(self: Ptau, i: usize) ParseError!G1.Affine {
        return pointAt(G1.Affine, try self.file.get(2), i);
    }

    /// `[τⁱ]₂`, `i < 2^p`.
    pub fn tauG2(self: Ptau, i: usize) ParseError!G2.Affine {
        return pointAt(G2.Affine, try self.file.get(3), i);
    }

    /// `[α]₁` (`[ατ⁰]₁`).
    pub fn alphaG1(self: Ptau) ParseError!G1.Affine {
        return pointAt(G1.Affine, try self.file.get(4), 0);
    }

    /// `[β]₁` (`[βτ⁰]₁`).
    pub fn betaG1(self: Ptau) ParseError!G1.Affine {
        return pointAt(G1.Affine, try self.file.get(5), 0);
    }

    /// `[β]₂`.
    pub fn betaG2(self: Ptau) ParseError!G2.Affine {
        return pointAt(G2.Affine, try self.file.get(6), 0);
    }
};

fn pointAt(comptime A: type, s: []const u8, i: usize) ParseError!A {
    const w: usize = if (A == G1.Affine) bin.g1_bytes else bin.g2_bytes;
    if (i >= s.len / w) return error.BadIndex;
    return if (A == G1.Affine) bin.g1FromBytes(s[i * w ..][0..bin.g1_bytes]) else bin.g2FromBytes(s[i * w ..][0..bin.g2_bytes]);
}
