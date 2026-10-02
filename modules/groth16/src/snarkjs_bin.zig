// SPDX-License-Identifier: MIT
//! The iden3 binary container shared by circom/snarkjs files (`.r1cs`,
//! `.wtns`, `.zkey`, `.ptau`) and the field/point encodings inside them.
//!
//! Everything here was established by RUNNING snarkjs@0.7.6 and circom 2.2.3
//! (both GPL-3.0, black box only — their source was not read) and comparing
//! the bytes they wrote with the decimal values their own `export json`
//! commands print for the same file; the recipe is `tools/snarkjs/gen.sh`.
//!
//! ## Container
//!
//! ```
//! magic[4] · version:u32 · n_sections:u32 ·
//!   n_sections × { type:u32 · size:u64 · payload[size] }
//! ```
//! All integers little-endian. ⚠ Section ORDER is not fixed: `groth16 setup`
//! writes zkey sections as 1,2,4,3,9,8,5,6,7,10 and `zkey contribute` as
//! 1..10, so a reader must go through the table, never assume positions.
//!
//! ## Encodings (measured, see `snarkjs_files_test.zig`)
//!
//! | where | element | bytes |
//! |---|---|---|
//! | `.r1cs` coefficients, `.wtns` values | `Fr` | 32 LE, canonical |
//! | `.zkey`/`.ptau` points | `Fp` coordinate | 32 LE, Montgomery (`x·2²⁵⁶ mod p`) |
//! | `.zkey` section 4 coefficients | `Fr` | 32 LE, DOUBLE Montgomery (`v·2⁵¹² mod r`) |
//! | G1 point | `x ‖ y` | 64; infinity = 64 zero bytes |
//! | G2 point | `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` | 128; infinity = 128 zero bytes |

const std = @import("std");
const bn254 = @import("bn254");

const Fp = bn254.Fp;
const Fp2 = bn254.Fp2;
const Fr = bn254.Fr;
const G1 = bn254.G1;
const G2 = bn254.G2;

/// Why a file was refused. Every refusal is a typed error: these parsers
/// read files that arrive from elsewhere (a ceremony download, a circuit
/// build), so nothing here may trust a length or an index it read.
pub const ParseError = error{
    /// Fewer bytes than the structure being read needs.
    Truncated,
    /// The 4-byte magic is not the expected file type.
    BadMagic,
    /// A container or section version this reader does not implement.
    UnsupportedVersion,
    /// The same section type appears twice.
    DuplicateSection,
    /// A section this file type requires is absent.
    MissingSection,
    /// A section's size disagrees with the counts the header announced.
    BadSectionSize,
    /// The file is not over BN254 (wrong field size or modulus).
    WrongField,
    /// A field element is `>=` its modulus.
    NonCanonical,
    /// A point is not on the curve.
    NotOnCurve,
    /// A count or index is out of the range the header allows.
    BadIndex,
    /// A feature of the format this reader does not implement (named per
    /// call site; e.g. circom custom gates, a non-Groth16 zkey).
    Unsupported,
};

pub const Section = struct {
    type: u32,
    payload: []const u8,
};

/// A parsed section table over borrowed bytes. At most `max_sections`
/// sections: every snarkjs file type uses section ids below 32.
pub const BinFile = struct {
    version: u32,
    sections: [max_sections]?[]const u8,

    pub const max_sections = 32;

    /// Parses the container header and section table of `bytes`, which must
    /// start with `magic`. Section payloads are borrowed slices of `bytes`.
    /// A section type `>= max_sections` is skipped (it is not one this
    /// module reads), a duplicate known type is refused.
    pub fn parse(bytes: []const u8, magic: *const [4]u8) ParseError!BinFile {
        if (bytes.len < 12) return error.Truncated;
        if (!std.mem.eql(u8, bytes[0..4], magic)) return error.BadMagic;
        var self: BinFile = .{
            .version = std.mem.readInt(u32, bytes[4..8], .little),
            .sections = @splat(null),
        };
        const n = std.mem.readInt(u32, bytes[8..12], .little);
        var off: usize = 12;
        for (0..n) |_| {
            if (bytes.len - off < 12) return error.Truncated;
            const ty = std.mem.readInt(u32, bytes[off..][0..4], .little);
            const size = std.mem.readInt(u64, bytes[off + 4 ..][0..8], .little);
            off += 12;
            if (size > bytes.len - off) return error.Truncated;
            const payload = bytes[off..][0..@intCast(size)];
            off += @intCast(size);
            if (ty >= max_sections) continue;
            if (self.sections[ty] != null) return error.DuplicateSection;
            self.sections[ty] = payload;
        }
        return self;
    }

    pub fn get(self: BinFile, ty: u32) ParseError![]const u8 {
        if (ty >= max_sections) return error.MissingSection;
        return self.sections[ty] orelse error.MissingSection;
    }
};

/// A bounds-checked little-endian cursor over one section's payload.
pub const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn take(self: *Cursor, n: usize) ParseError![]const u8 {
        if (self.bytes.len - self.pos < n) return error.Truncated;
        defer self.pos += n;
        return self.bytes[self.pos..][0..n];
    }

    pub fn int(self: *Cursor, comptime T: type) ParseError!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }

    pub fn rest(self: Cursor) usize {
        return self.bytes.len - self.pos;
    }
};

// ── container writer ───────────────────────────────────────────────────────

/// Writes the container header for `n_sections` sections.
pub fn writeHeader(w: *std.Io.Writer, magic: *const [4]u8, version: u32, n_sections: u32) std.Io.Writer.Error!void {
    try w.writeAll(magic);
    try w.writeInt(u32, version, .little);
    try w.writeInt(u32, n_sections, .little);
}

/// Writes one section header; the caller then writes exactly `size` bytes.
pub fn writeSectionHeader(w: *std.Io.Writer, ty: u32, size: u64) std.Io.Writer.Error!void {
    try w.writeInt(u32, ty, .little);
    try w.writeInt(u64, size, .little);
}

// ── field moduli as they appear in file headers ───────────────────────────

fn reverse32(b: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (0..32) |i| out[i] = b[31 - i];
    return out;
}

/// `r` as 32 little-endian bytes, the form `.r1cs`/`.wtns`/`.zkey` headers carry.
pub const r_le: [32]u8 = reverse32(bn254.scalar.r_bytes);
/// `p` (the base field) as 32 little-endian bytes, the form `.zkey`/`.ptau` headers carry.
pub const q_le: [32]u8 = reverse32(bn254.fp.p_bytes);

/// Reads `n8:u32 · prime[n8]` and refuses anything that is not
/// `32 · expected`.
pub fn expectPrime(c: *Cursor, expected: *const [32]u8) ParseError!void {
    const n8 = try c.int(u32);
    if (n8 != 32) return error.WrongField;
    if (!std.mem.eql(u8, try c.take(32), expected)) return error.WrongField;
}

pub fn writePrime(w: *std.Io.Writer, prime: *const [32]u8) std.Io.Writer.Error!void {
    try w.writeInt(u32, 32, .little);
    try w.writeAll(prime);
}

// ── Fr ──────────────────────────────────────────────────────────────────────

/// `Fr` from 32 canonical little-endian bytes (`.r1cs`, `.wtns`).
pub fn frFromLe(b: *const [32]u8) ParseError!Fr {
    return Fr.fromBytes(reverse32(b.*)) catch error.NonCanonical;
}

pub fn frToLe(v: Fr) [32]u8 {
    return reverse32(v.toBytes());
}

fn hexBe(comptime hex: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// `Fr` from a zkey coefficient: 32 LE bytes holding `v·2⁵¹² mod r`.
/// `r2_inv` is `r2Inv()`, computed once by the caller (an inversion per
/// coefficient was 13 % of loading a 10k-constraint key, measured).
pub fn frFromMont2Le(b: *const [32]u8, r2_inv: Fr) ParseError!Fr {
    return (try frFromLe(b)).mul(r2_inv);
}

/// The inverse of `frFromMont2Le`; `r2_val` is `r2()`.
pub fn frToMont2Le(v: Fr, r2_val: Fr) [32]u8 {
    return frToLe(v.mul(r2_val));
}

/// `2⁵¹² mod r`, computed as `(2²⁵⁶ mod r)²` so no second hand-typed
/// constant can disagree with the first.
pub fn r2() Fr {
    const r_mod = Fr.reduceWide(&(([_]u8{1} ++ [_]u8{0} ** 32)));
    return r_mod.mul(r_mod);
}

pub fn r2Inv() Fr {
    return r2().inv() catch unreachable;
}

// ── Fp (Montgomery, LE) ─────────────────────────────────────────────────────

/// `Fp` from 32 LE bytes holding `x·2²⁵⁶ mod p`.
///
/// `bn254.Fp` keeps its value as Montgomery limbs with the same `R = 2²⁵⁶`,
/// so the file's integer IS the internal representation: validate that it is
/// `< p`, then load it. `snarkjs_files_test.zig` pins this against the
/// decimal values snarkjs prints, so a change of `bn254`'s representation
/// fails loudly instead of decoding garbage.
pub fn fpFromMontLe(b: *const [32]u8) ParseError!Fp {
    var limbs: [4]u64 = undefined;
    for (&limbs, 0..) |*l, i| l.* = std.mem.readInt(u64, b[i * 8 ..][0..8], .little);
    // Range check through the public constructor (it refuses `>= p`).
    _ = Fp.fromBytes(reverse32(b.*)) catch return error.NonCanonical;
    return .{ .limbs = limbs };
}

pub fn fpToMontLe(v: Fp) [32]u8 {
    var out: [32]u8 = undefined;
    for (v.limbs, 0..) |l, i| std.mem.writeInt(u64, out[i * 8 ..][0..8], l, .little);
    return out;
}

// ── points ──────────────────────────────────────────────────────────────────

pub const g1_bytes = 64;
pub const g2_bytes = 128;

/// `count · width` as a byte length, or `BadSectionSize` if it does not fit a
/// `usize`. Counts come from file headers; on a 32-bit target a plain product
/// wraps and could equal a real (small) section's length (review 2026-10-02).
pub fn byteLen(count: u64, width: u64) ParseError!usize {
    const n = std.math.mul(u64, count, width) catch return error.BadSectionSize;
    return std.math.cast(usize, n) orelse error.BadSectionSize;
}

/// A G1 point from 64 bytes of Montgomery-LE `x ‖ y`; all-zero = infinity.
/// Refuses a point off the curve (G1's cofactor is 1, so on-curve is
/// in-subgroup).
pub fn g1FromBytes(b: *const [g1_bytes]u8) ParseError!G1.Affine {
    if (std.mem.allEqual(u8, b, 0)) return G1.Affine.identity;
    const p: G1.Affine = .{ .x = try fpFromMontLe(b[0..32]), .y = try fpFromMontLe(b[32..64]) };
    if (!G1.Jacobian.fromAffine(p).isOnCurve()) return error.NotOnCurve;
    return p;
}

pub fn g1ToBytes(p: G1.Affine) [g1_bytes]u8 {
    if (p.infinity) return @splat(0);
    return fpToMontLe(p.x) ++ fpToMontLe(p.y);
}

/// A G2 point from 128 bytes; all-zero = infinity. Checks the twist
/// equation only: the `[r]P == O` subgroup check costs a full scalar
/// multiplication per point, so it belongs to `phase2.verify` (the step that
/// decides whether a key can be trusted), not to every load.
pub fn g2FromBytes(b: *const [g2_bytes]u8) ParseError!G2.Affine {
    if (std.mem.allEqual(u8, b, 0)) return G2.Affine.identity;
    const p: G2.Affine = .{
        .x = .{ .c0 = try fpFromMontLe(b[0..32]), .c1 = try fpFromMontLe(b[32..64]) },
        .y = .{ .c0 = try fpFromMontLe(b[64..96]), .c1 = try fpFromMontLe(b[96..128]) },
    };
    if (!G2.Jacobian.fromAffine(p).isOnCurve()) return error.NotOnCurve;
    return p;
}

pub fn g2ToBytes(p: G2.Affine) [g2_bytes]u8 {
    if (p.infinity) return @splat(0);
    return fpToMontLe(p.x.c0) ++ fpToMontLe(p.x.c1) ++ fpToMontLe(p.y.c0) ++ fpToMontLe(p.y.c1);
}

/// Decodes `out.len` consecutive G1 points from `bytes` (which must be
/// exactly `out.len · 64` long).
pub fn g1Slice(bytes: []const u8, out: []G1.Affine) ParseError!void {
    if (bytes.len != try byteLen(out.len, g1_bytes)) return error.BadSectionSize;
    for (out, 0..) |*p, i| p.* = try g1FromBytes(bytes[i * g1_bytes ..][0..g1_bytes]);
}

pub fn g2Slice(bytes: []const u8, out: []G2.Affine) ParseError!void {
    if (bytes.len != try byteLen(out.len, g2_bytes)) return error.BadSectionSize;
    for (out, 0..) |*p, i| p.* = try g2FromBytes(bytes[i * g2_bytes ..][0..g2_bytes]);
}

// ── tests ────────────────────────────────────────────────────────────────

test "container: section table, out-of-order sections, duplicate refused" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeHeader(&w, "test", 1, 2);
    try writeSectionHeader(&w, 3, 2);
    try w.writeAll("ab");
    try writeSectionHeader(&w, 1, 1);
    try w.writeAll("c");
    const f = try BinFile.parse(w.buffered(), "test");
    try std.testing.expectEqualStrings("ab", try f.get(3));
    try std.testing.expectEqualStrings("c", try f.get(1));
    try std.testing.expectError(error.MissingSection, f.get(2));
    try std.testing.expectError(error.BadMagic, BinFile.parse(w.buffered(), "zkey"));

    var dup: [64]u8 = undefined;
    var w2: std.Io.Writer = .fixed(&dup);
    try writeHeader(&w2, "test", 1, 2);
    try writeSectionHeader(&w2, 1, 0);
    try writeSectionHeader(&w2, 1, 0);
    try std.testing.expectError(error.DuplicateSection, BinFile.parse(w2.buffered(), "test"));
}

test "container: a section size past the end is Truncated, not a slice panic" {
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeHeader(&w, "test", 1, 1);
    try writeSectionHeader(&w, 1, std.math.maxInt(u64));
    try std.testing.expectError(error.Truncated, BinFile.parse(w.buffered(), "test"));
}

test "Fp Montgomery codec round-trips and refuses >= p" {
    const g = G1.Affine.generator;
    const enc = g1ToBytes(g);
    const dec = try g1FromBytes(&enc);
    try std.testing.expect(dec.x.eql(g.x) and dec.y.eql(g.y));
    var bad: [32]u8 = q_le;
    try std.testing.expectError(error.NonCanonical, fpFromMontLe(&bad));
    bad[0] -%= 1; // p − 1 is canonical
    _ = try fpFromMontLe(&bad);
}

test "double-Montgomery Fr codec round-trips" {
    const v = Fr.fromBytes(hexBe("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")) catch unreachable;
    const enc = frToMont2Le(v, r2());
    try std.testing.expect((try frFromMont2Le(&enc, r2Inv())).eql(v));
    try std.testing.expect(r2().mul(r2Inv()).eql(Fr.one));
}

test "off-curve point refused" {
    var enc = g1ToBytes(G1.Affine.generator);
    enc[40] ^= 1;
    try std.testing.expectError(error.NotOnCurve, g1FromBytes(&enc));
}

test "off-curve G2 point refused" {
    var enc = g2ToBytes(G2.Affine.generator);
    enc[100] ^= 1;
    try std.testing.expectError(error.NotOnCurve, g2FromBytes(&enc));
}
