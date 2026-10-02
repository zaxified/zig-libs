// SPDX-License-Identifier: MIT
//! snarkjs `.zkey` (Groth16 proving key) — reader and writer.
//!
//! Layout established black-box from snarkjs@0.7.6 output (see
//! `snarkjs_bin.zig` for the container and encodings, `tools/snarkjs/gen.sh`
//! for the recipe):
//!
//! | section | contents |
//! |---|---|
//! | 1 | `protocol:u32` — 1 = Groth16 (the only one read here) |
//! | 2 | `n8q·q · n8r·r · n_vars:u32 · n_public:u32 · domain_size:u32 · α₁ · β₁ · β₂ · γ₂ · δ₁ · δ₂` |
//! | 3 | IC — `n_public + 1` G1 |
//! | 4 | `n:u32` × `{matrix:u32 (0 = A, 1 = B), constraint:u32, signal:u32, value}` (value double-Montgomery) |
//! | 5, 6, 7 | `[Aⱼ(τ)]₁`, `[Bⱼ(τ)]₁`, `[Bⱼ(τ)]₂` — `n_vars` points each |
//! | 8 | `[(βAⱼ+αBⱼ+Cⱼ)(τ)/δ]₁` for the private signals — `n_vars − n_public − 1` G1 |
//! | 9 | H — `domain_size` G1: `[L^{2n}_{2i+1}(τ)/δ]₁`, the Lagrange basis of the DOUBLED domain at its odd points (see `zkprove.zig`) |
//! | 10 | `circuit_hash[64] · n:u32 · n × contribution` |
//!
//! ⚠ The C matrix is NOT stored: on the evaluation domain `C = A·B` for a
//! satisfying witness, which is all the prover needs. The coefficient list
//! carries snarkjs's extra rows `A[n_constraints + i][i] = 1`, one per public
//! signal `i ∈ 0..=n_public`, which make the public `Aᵢ` linearly independent.

const std = @import("std");
const bn254 = @import("bn254");
const bin = @import("snarkjs_bin.zig");

const Fr = bn254.Fr;
const G1 = bn254.G1;
const G2 = bn254.G2;
const Allocator = std.mem.Allocator;
const ParseError = bin.ParseError;

pub const magic = "zkey";

pub const Coef = struct {
    matrix: Matrix,
    constraint: u32,
    signal: u32,
    value: Fr,

    pub const Matrix = enum(u32) { a = 0, b = 1 };
};

/// One phase-2 contribution record, kept as snarkjs wrote it. Only
/// `delta_after` is interpreted by this module (`phase2.verify` checks that
/// the last one is the key's δ₁); the proof-of-knowledge fields are carried
/// through unchanged so a file round-trips byte-exactly.
pub const Contribution = struct {
    delta_after: G1.Affine,
    g1_s: G1.Affine,
    g1_sx: G1.Affine,
    g2_spx: G2.Affine,
    transcript: [64]u8,
    type: u32,
    /// The raw parameter block (`{id:u8, len:u8, bytes}*`), owned.
    params: []const u8,

    /// The contributor's name (parameter id 1), if present.
    pub fn name(self: Contribution) ?[]const u8 {
        var i: usize = 0;
        while (i + 2 <= self.params.len) {
            const id = self.params[i];
            const len = self.params[i + 1];
            if (self.params.len - i - 2 < len) return null;
            if (id == 1) return self.params[i + 2 ..][0..len];
            i += 2 + len;
        }
        return null;
    }
};

pub const ZKey = struct {
    n_vars: u32,
    n_public: u32,
    domain_size: u32,
    alpha_g1: G1.Affine,
    beta_g1: G1.Affine,
    beta_g2: G2.Affine,
    gamma_g2: G2.Affine,
    delta_g1: G1.Affine,
    delta_g2: G2.Affine,
    ic: []G1.Affine,
    coefs: []Coef,
    a: []G1.Affine,
    b_g1: []G1.Affine,
    b_g2: []G2.Affine,
    c: []G1.Affine,
    h: []G1.Affine,
    circuit_hash: [64]u8,
    contributions: []Contribution,
    /// Section order the file had (or `default_order` for a new key), so a
    /// write reproduces a canonical input (sections 1–10, nothing else) byte
    /// for byte. Other sections are not kept.
    order: [10]u8 = default_order,

    /// The order `snarkjs groth16 setup` writes.
    pub const default_order: [10]u8 = .{ 1, 2, 4, 3, 9, 8, 5, 6, 7, 10 };

    pub fn deinit(self: *ZKey, allocator: Allocator) void {
        allocator.free(self.ic);
        allocator.free(self.coefs);
        allocator.free(self.a);
        allocator.free(self.b_g1);
        allocator.free(self.b_g2);
        allocator.free(self.c);
        allocator.free(self.h);
        for (self.contributions) |c| allocator.free(c.params);
        allocator.free(self.contributions);
        self.* = undefined;
    }

    /// `log2(domain_size)`.
    pub fn power(self: ZKey) u5 {
        return @intCast(std.math.log2_int(u32, self.domain_size));
    }

    /// The matching verifying key. `ic` is borrowed from `self`.
    pub fn verifyingKey(self: ZKey) bn254.Groth16VerifyingKey {
        return .{
            .alpha_g1 = self.alpha_g1,
            .beta_g2 = self.beta_g2,
            .gamma_g2 = self.gamma_g2,
            .delta_g2 = self.delta_g2,
            .ic = self.ic,
        };
    }
};

pub const Error = ParseError || Allocator.Error;

/// Largest domain BN254's `Fr` has roots of unity for (2-adicity 28).
pub const max_domain_power = 28;

/// Parses a Groth16 `.zkey`. All points are checked on-curve; G2 subgroup
/// membership is left to `phase2.verify` (see `snarkjs_bin.g2FromBytes`).
/// The result owns its arrays; `bytes` may be freed afterwards.
pub fn parse(allocator: Allocator, bytes: []const u8) Error!ZKey {
    const f = try bin.BinFile.parse(bytes, magic);
    if (f.version != 1) return error.UnsupportedVersion;

    {
        var c: bin.Cursor = .{ .bytes = try f.get(1) };
        if (try c.int(u32) != 1) return error.Unsupported; // not Groth16
    }

    var order: [10]u8 = undefined;
    {
        // Recover the section order from the table itself.
        var seen: usize = 0;
        var off: usize = 12;
        const n = std.mem.readInt(u32, bytes[8..12], .little);
        for (0..n) |_| {
            const ty = std.mem.readInt(u32, bytes[off..][0..4], .little);
            const size = std.mem.readInt(u64, bytes[off + 4 ..][0..8], .little);
            off += 12 + @as(usize, @intCast(size));
            if (ty >= 1 and ty <= 10) {
                if (seen == 10) return error.DuplicateSection;
                order[seen] = @intCast(ty);
                seen += 1;
            }
        }
        if (seen != 10) return error.MissingSection;
    }

    var hc: bin.Cursor = .{ .bytes = try f.get(2) };
    try bin.expectPrime(&hc, &bin.q_le);
    try bin.expectPrime(&hc, &bin.r_le);
    const n_vars = try hc.int(u32);
    const n_public = try hc.int(u32);
    const domain_size = try hc.int(u32);
    if (n_vars == 0 or n_public >= n_vars) return error.BadIndex;
    if (domain_size < 2 or !std.math.isPowerOfTwo(domain_size) or
        domain_size > (@as(u32, 1) << max_domain_power)) return error.BadIndex;
    if (hc.rest() != 3 * bin.g1_bytes + 3 * bin.g2_bytes) return error.BadSectionSize;

    var z: ZKey = .{
        .n_vars = n_vars,
        .n_public = n_public,
        .domain_size = domain_size,
        .alpha_g1 = try bin.g1FromBytes((try hc.take(64))[0..64]),
        .beta_g1 = try bin.g1FromBytes((try hc.take(64))[0..64]),
        .beta_g2 = try bin.g2FromBytes((try hc.take(128))[0..128]),
        .gamma_g2 = try bin.g2FromBytes((try hc.take(128))[0..128]),
        .delta_g1 = try bin.g1FromBytes((try hc.take(64))[0..64]),
        .delta_g2 = try bin.g2FromBytes((try hc.take(128))[0..128]),
        .ic = &.{},
        .coefs = &.{},
        .a = &.{},
        .b_g1 = &.{},
        .b_g2 = &.{},
        .c = &.{},
        .h = &.{},
        .circuit_hash = undefined,
        .contributions = &.{},
        .order = order,
    };
    errdefer z.deinit(allocator);

    z.ic = try g1Section(allocator, f, 3, n_public + 1);
    z.a = try g1Section(allocator, f, 5, n_vars);
    z.b_g1 = try g1Section(allocator, f, 6, n_vars);
    {
        // Size before allocation: every count above came from the header.
        const b2 = try f.get(7);
        if (b2.len != try bin.byteLen(n_vars, bin.g2_bytes)) return error.BadSectionSize;
        z.b_g2 = try allocator.alloc(G2.Affine, n_vars);
        try bin.g2Slice(b2, z.b_g2);
    }
    z.c = try g1Section(allocator, f, 8, n_vars - n_public - 1);
    z.h = try g1Section(allocator, f, 9, domain_size);

    {
        var c: bin.Cursor = .{ .bytes = try f.get(4) };
        const n = try c.int(u32);
        if (c.rest() != try bin.byteLen(n, 44)) return error.BadSectionSize;
        z.coefs = try allocator.alloc(Coef, n);
        const r2_inv = bin.r2Inv();
        for (z.coefs) |*co| {
            const m = try c.int(u32);
            if (m > 1) return error.BadIndex;
            co.* = .{
                .matrix = @enumFromInt(m),
                .constraint = try c.int(u32),
                .signal = try c.int(u32),
                .value = try bin.frFromMont2Le((try c.take(32))[0..32], r2_inv),
            };
            if (co.constraint >= domain_size or co.signal >= n_vars) return error.BadIndex;
        }
    }

    {
        var c: bin.Cursor = .{ .bytes = try f.get(10) };
        z.circuit_hash = (try c.take(64))[0..64].*;
        const n = try c.int(u32);
        // Each record is at least 392 bytes; refuse a count the section cannot hold
        // before allocating for it.
        if (n > c.rest() / 392) return error.BadSectionSize;
        const list = try allocator.alloc(Contribution, n);
        var filled: usize = 0;
        errdefer {
            for (list[0..filled]) |k| allocator.free(k.params);
            allocator.free(list);
        }
        for (list) |*k| {
            k.delta_after = try bin.g1FromBytes((try c.take(64))[0..64]);
            k.g1_s = try bin.g1FromBytes((try c.take(64))[0..64]);
            k.g1_sx = try bin.g1FromBytes((try c.take(64))[0..64]);
            k.g2_spx = try bin.g2FromBytes((try c.take(128))[0..128]);
            k.transcript = (try c.take(64))[0..64].*;
            k.type = try c.int(u32);
            const plen = try c.int(u32);
            k.params = try allocator.dupe(u8, try c.take(plen));
            filled += 1;
        }
        if (c.rest() != 0) return error.BadSectionSize;
        z.contributions = list;
    }
    return z;
}

/// Decodes section `ty` as exactly `n` G1 points. The size is checked BEFORE
/// allocating: `n` comes from the file's header, so a forged count must cost
/// a refusal, not an allocation of `n · 72` bytes.
fn g1Section(allocator: Allocator, f: bin.BinFile, ty: u32, n: usize) Error![]G1.Affine {
    const bytes = try f.get(ty);
    if (bytes.len != try bin.byteLen(n, bin.g1_bytes)) return error.BadSectionSize;
    const out = try allocator.alloc(G1.Affine, n);
    errdefer allocator.free(out);
    try bin.g1Slice(bytes, out);
    return out;
}

// ── writer ────────────────────────────────────────────────────────────────

fn sectionSize(z: ZKey, ty: u8) u64 {
    return switch (ty) {
        1 => 4,
        2 => 2 * 36 + 12 + 3 * bin.g1_bytes + 3 * bin.g2_bytes,
        3 => z.ic.len * bin.g1_bytes,
        4 => 4 + z.coefs.len * 44,
        5 => z.a.len * bin.g1_bytes,
        6 => z.b_g1.len * bin.g1_bytes,
        7 => z.b_g2.len * bin.g2_bytes,
        8 => z.c.len * bin.g1_bytes,
        9 => z.h.len * bin.g1_bytes,
        10 => blk: {
            var n: u64 = 68;
            for (z.contributions) |k| n += 3 * 64 + 128 + 64 + 8 + k.params.len;
            break :blk n;
        },
        else => unreachable,
    };
}

/// Writes `z` in snarkjs's `.zkey` format, sections in `z.order`.
pub fn write(z: ZKey, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try bin.writeHeader(w, magic, 1, 10);
    for (z.order) |ty| {
        try bin.writeSectionHeader(w, ty, sectionSize(z, ty));
        switch (ty) {
            1 => try w.writeInt(u32, 1, .little),
            2 => {
                try bin.writePrime(w, &bin.q_le);
                try bin.writePrime(w, &bin.r_le);
                try w.writeInt(u32, z.n_vars, .little);
                try w.writeInt(u32, z.n_public, .little);
                try w.writeInt(u32, z.domain_size, .little);
                try w.writeAll(&bin.g1ToBytes(z.alpha_g1));
                try w.writeAll(&bin.g1ToBytes(z.beta_g1));
                try w.writeAll(&bin.g2ToBytes(z.beta_g2));
                try w.writeAll(&bin.g2ToBytes(z.gamma_g2));
                try w.writeAll(&bin.g1ToBytes(z.delta_g1));
                try w.writeAll(&bin.g2ToBytes(z.delta_g2));
            },
            3 => for (z.ic) |p| try w.writeAll(&bin.g1ToBytes(p)),
            4 => {
                try w.writeInt(u32, @intCast(z.coefs.len), .little);
                const r2 = bin.r2();
                for (z.coefs) |co| {
                    try w.writeInt(u32, @intFromEnum(co.matrix), .little);
                    try w.writeInt(u32, co.constraint, .little);
                    try w.writeInt(u32, co.signal, .little);
                    try w.writeAll(&bin.frToMont2Le(co.value, r2));
                }
            },
            5 => for (z.a) |p| try w.writeAll(&bin.g1ToBytes(p)),
            6 => for (z.b_g1) |p| try w.writeAll(&bin.g1ToBytes(p)),
            7 => for (z.b_g2) |p| try w.writeAll(&bin.g2ToBytes(p)),
            8 => for (z.c) |p| try w.writeAll(&bin.g1ToBytes(p)),
            9 => for (z.h) |p| try w.writeAll(&bin.g1ToBytes(p)),
            10 => {
                try w.writeAll(&z.circuit_hash);
                try w.writeInt(u32, @intCast(z.contributions.len), .little);
                for (z.contributions) |k| {
                    try w.writeAll(&bin.g1ToBytes(k.delta_after));
                    try w.writeAll(&bin.g1ToBytes(k.g1_s));
                    try w.writeAll(&bin.g1ToBytes(k.g1_sx));
                    try w.writeAll(&bin.g2ToBytes(k.g2_spx));
                    try w.writeAll(&k.transcript);
                    try w.writeInt(u32, k.type, .little);
                    try w.writeInt(u32, @intCast(k.params.len), .little);
                    try w.writeAll(k.params);
                }
            },
            else => unreachable,
        }
    }
}

/// `write` into a freshly allocated buffer.
pub fn toBytes(allocator: Allocator, z: ZKey) Allocator.Error![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    write(z, &aw.writer) catch return error.OutOfMemory;
    return aw.toOwnedSlice();
}
