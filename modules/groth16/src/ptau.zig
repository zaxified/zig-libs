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
//! `readCut` goes further for a file that does not fit in memory (the 2²⁸
//! ceremony is ~150 GB): it reads, by position, only the prefix of each
//! section a smaller power needs and returns those bytes as a `.ptau` of that
//! power — the shape snarkjs's `powersoftau truncate` writes, minus the
//! contribution chain — which `parse` then reads as usual.

const std = @import("std");
const bn254 = @import("bn254");
const bin = @import("snarkjs_bin.zig");

const G1 = bn254.G1;
const G2 = bn254.G2;
const ParseError = bin.ParseError;
const Allocator = std.mem.Allocator;

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
        const s = try self.file.get(@backingInt(basis));
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
        return bin.g2FromBytesUnchecked(s[i * bin.g2_bytes ..][0..bin.g2_bytes]); // the .ptau is trusted (phase2.verify)
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
    return if (A == G1.Affine) bin.g1FromBytes(s[i * w ..][0..bin.g1_bytes]) else bin.g2FromBytesUnchecked(s[i * w ..][0..bin.g2_bytes]);
}

// ── positional source ───────────────────────────────────────────────────────

pub const ReadError = ParseError || Allocator.Error || std.Io.File.ReadPositionalError || error{
    /// `power` is above the file's own power.
    PowerTooLarge,
};

/// Section ids `readCut` copies, in the order it writes them.
const cut_sections = [_]u32{ 1, 2, 3, 4, 5, 6, 12, 13, 14, 15 };

/// Bytes of section `ty` a `.ptau` of `power` holds (section 12 has one level
/// more than the others, except at 2²⁸, see `Ptau.parse`).
fn cutLen(ty: u32, power: u5, header_len: usize) error{BadSectionSize}!usize {
    const n: u64 = @as(u64, 1) << power;
    return switch (ty) {
        1 => header_len,
        2 => bin.byteLen(2 * n - 1, bin.g1_bytes),
        3 => bin.byteLen(n, bin.g2_bytes),
        4, 5 => bin.byteLen(n, bin.g1_bytes),
        6 => bin.g2_bytes,
        12 => bin.byteLen(if (power < 28) 4 * n - 1 else 2 * n - 1, bin.g1_bytes),
        13 => bin.byteLen(2 * n - 1, bin.g2_bytes),
        14, 15 => bin.byteLen(2 * n - 1, bin.g1_bytes),
        else => unreachable,
    } catch error.BadSectionSize;
}

fn readExact(file: std.Io.File, io: std.Io, buf: []u8, offset: u64) ReadError!void {
    if (try file.readPositionalAll(io, buf, offset) != buf.len) return error.Truncated;
}

/// Reads from `file` (a `.ptau` of power `P`, prepared for phase 2 or not)
/// only what a `.ptau` of `power <= P` holds, by position, and returns that
/// file's bytes (caller frees): section 1 with `power` in place of `P`, the
/// prefix of sections 2–6 and 12–15 (every one is ordered by power, so a
/// prefix is the smaller file's section), and no contribution chain. A
/// circuit of `2^power` rows needs `power` (`phase2.newZkey` refuses a
/// smaller file with `error.PtauTooSmall`). The result is checked by `parse`
/// before it is returned. Memory: the cut, about `2^power · 704` bytes for a
/// prepared file; nothing is read beyond it but the section table.
pub fn readCut(allocator: Allocator, io: std.Io, file: std.Io.File, power: u5) ReadError![]u8 {
    var head: [12]u8 = undefined;
    try readExact(file, io, &head, 0);
    if (!std.mem.eql(u8, head[0..4], "ptau")) return error.BadMagic;
    if (std.mem.readInt(u32, head[4..8], .little) != 1) return error.UnsupportedVersion;
    const n_sections = std.mem.readInt(u32, head[8..12], .little);

    // The section table: where each section's payload starts and its size.
    var at: [bin.BinFile.max_sections]?struct { off: u64, size: u64 } = @splat(null);
    var off: u64 = 12;
    for (0..n_sections) |_| {
        var sh: [12]u8 = undefined;
        try readExact(file, io, &sh, off);
        const ty = std.mem.readInt(u32, sh[0..4], .little);
        const size = std.mem.readInt(u64, sh[4..12], .little);
        off += 12;
        if (ty < at.len) {
            if (at[ty] != null) return error.DuplicateSection;
            at[ty] = .{ .off = off, .size = size };
        }
        off = std.math.add(u64, off, size) catch return error.Truncated;
    }

    // Section 1: n8 · q · power · ceremony_power.
    const s1 = at[1] orelse return error.MissingSection;
    if (s1.size != 4 + 32 + 4 + 4) return error.BadSectionSize;
    var h1: [44]u8 = undefined;
    try readExact(file, io, &h1, s1.off);
    const src_power = std.mem.readInt(u32, h1[36..40], .little);
    if (src_power < 1 or src_power > 28) return error.BadIndex;
    if (power < 1) return error.BadIndex;
    if (power > src_power) return error.PowerTooLarge;
    std.mem.writeInt(u32, h1[36..40], power, .little);

    var total: usize = 12;
    var count: u32 = 0;
    for (cut_sections) |ty| {
        const sec = at[ty] orelse continue;
        const len = try cutLen(ty, power, h1.len);
        if (len > sec.size) return error.BadSectionSize;
        total = std.math.add(usize, total, 12 + len) catch return error.BadSectionSize;
        count += 1;
    }
    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);
    @memcpy(out[0..8], head[0..8]);
    std.mem.writeInt(u32, out[8..12], count, .little);
    var w: usize = 12;
    for (cut_sections) |ty| {
        const sec = at[ty] orelse continue;
        const len = try cutLen(ty, power, h1.len);
        std.mem.writeInt(u32, out[w..][0..4], ty, .little);
        std.mem.writeInt(u64, out[w + 4 ..][0..8], len, .little);
        w += 12;
        if (ty == 1) @memcpy(out[w..][0..len], &h1) else try readExact(file, io, out[w..][0..len], sec.off);
        w += len;
    }
    _ = try Ptau.parse(out);
    return out;
}

test "readCut: reads a smaller power by position; what it returns parses and agrees with the whole file" {
    const testing = std.testing;
    const io = testing.io;
    const full = @embedFile("testdata/snarkjs/pot.ptau");
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "pot.ptau", .data = full });
    const file = try tmp.dir.openFile(io, "pot.ptau", .{});
    defer file.close(io);

    const whole = try Ptau.parse(full);
    try testing.expectEqual(@as(u5, 4), whole.power);
    for ([_]u5{ 1, 2, 3, 4 }) |p| {
        const cut = try readCut(testing.allocator, io, file, p);
        defer testing.allocator.free(cut);
        const z = try Ptau.parse(cut);
        try testing.expectEqual(p, z.power);
        try testing.expectEqual(whole.ceremony_power, z.ceremony_power);
        // Every level the smaller file has is the whole file's level.
        for (0..@as(usize, p) + 2) |lv| {
            const level: u5 = @intCast(lv);
            try testing.expectEqualSlices(u8, try whole.lagrangeBytes(.tau_g1, level), try z.lagrangeBytes(.tau_g1, level));
            if (level <= p) for ([_]Ptau.Basis{ .tau_g2, .alpha_tau_g1, .beta_tau_g1 }) |b| {
                try testing.expectEqualSlices(u8, try whole.lagrangeBytes(b, level), try z.lagrangeBytes(b, level));
            };
        }
        try testing.expectError(error.BadIndex, z.lagrangeBytes(.tau_g1, p + 2));
        try testing.expect((try z.betaG2()).x.eql((try whole.betaG2()).x));
        if (p == 4) {
            // The whole power: the file minus its contribution chain.
            try testing.expectEqual(full.len - 12 - (try whole.file.get(7)).len, cut.len);
        }
    }
    try testing.expectError(error.PowerTooLarge, readCut(testing.allocator, io, file, 5));
    try testing.expectError(error.BadIndex, readCut(testing.allocator, io, file, 0));

    // A file cut short inside a section's payload: refused, not misread.
    try tmp.dir.writeFile(io, .{ .sub_path = "short.ptau", .data = full[0 .. full.len - 100] });
    const short = try tmp.dir.openFile(io, "short.ptau", .{});
    defer short.close(io);
    try testing.expectError(error.Truncated, readCut(testing.allocator, io, short, 4));
    try tmp.dir.writeFile(io, .{ .sub_path = "magic.ptau", .data = "zkey\x01\x00\x00\x00\x00\x00\x00\x00" });
    const bad = try tmp.dir.openFile(io, "magic.ptau", .{});
    defer bad.close(io);
    try testing.expectError(error.BadMagic, readCut(testing.allocator, io, bad, 1));
}
