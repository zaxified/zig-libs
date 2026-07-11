// SPDX-License-Identifier: MIT
//! address — FIPS 205 §4.2 hash addresses (ADRS).
//!
//! A 32-byte big-endian structure that makes every hash call in the SLH-DSA
//! hypertree domain-separated: layer (4 B) || tree address (12 B) || type
//! (4 B) || three type-specific 4-byte words. The SHA2 instantiations
//! (§11.2, "compressed ADRS") drop the always-zero padding bytes down to
//! 22 bytes; `compressed()` implements exactly that byte selection.

const std = @import("std");

/// ADRS type constants (FIPS 205 Table 1).
pub const Type = enum(u32) {
    wots_hash = 0,
    wots_pk = 1,
    tree = 2,
    fors_tree = 3,
    fors_roots = 4,
    wots_prf = 5,
    fors_prf = 6,
};

/// The 32-byte ADRS with the §4.2 member functions. Plain value type —
/// copy freely (callers snapshot it before recursing down a subtree).
pub const Address = struct {
    bytes: [32]u8 = @splat(0),

    pub fn setLayer(a: *Address, layer: u32) void {
        std.mem.writeInt(u32, a.bytes[0..4], layer, .big);
    }

    /// Tree address is 12 bytes in ADRS but at most 64 bits in FIPS 205
    /// (h - h/d <= 64 for every parameter set); bytes 4..8 stay zero.
    pub fn setTree(a: *Address, tree: u64) void {
        std.mem.writeInt(u64, a.bytes[8..16], tree, .big);
    }

    /// setTypeAndClear (§4.2): set the type word AND zero the three
    /// type-specific words that follow it.
    pub fn setTypeAndClear(a: *Address, t: Type) void {
        std.mem.writeInt(u32, a.bytes[16..20], @intFromEnum(t), .big);
        @memset(a.bytes[20..32], 0);
    }

    pub fn setKeyPair(a: *Address, i: u32) void {
        std.mem.writeInt(u32, a.bytes[20..24], i, .big);
    }

    pub fn getKeyPair(a: Address) u32 {
        return std.mem.readInt(u32, a.bytes[20..24], .big);
    }

    pub fn setChain(a: *Address, i: u32) void {
        std.mem.writeInt(u32, a.bytes[24..28], i, .big);
    }

    /// Same word as the chain address, used by tree/FORS-tree types.
    pub fn setTreeHeight(a: *Address, z: u32) void {
        std.mem.writeInt(u32, a.bytes[24..28], z, .big);
    }

    pub fn setHash(a: *Address, i: u32) void {
        std.mem.writeInt(u32, a.bytes[28..32], i, .big);
    }

    /// Same word as the hash address, used by tree/FORS-tree types.
    pub fn setTreeIndex(a: *Address, i: u32) void {
        std.mem.writeInt(u32, a.bytes[28..32], i, .big);
    }

    pub fn getTreeIndex(a: Address) u32 {
        return std.mem.readInt(u32, a.bytes[28..32], .big);
    }

    /// Compressed 22-byte ADRS for the SHA2 instantiations (§11.2):
    /// ADRS[3] || ADRS[8..16] || ADRS[19] || ADRS[20..32].
    pub fn compressed(a: Address) [22]u8 {
        var out: [22]u8 = undefined;
        out[0] = a.bytes[3];
        out[1..9].* = a.bytes[8..16].*;
        out[9] = a.bytes[19];
        out[10..22].* = a.bytes[20..32].*;
        return out;
    }
};

test "member functions hit the FIPS 205 byte offsets" {
    var a: Address = .{};
    a.setLayer(0x01020304);
    a.setTree(0x1112131415161718);
    a.setTypeAndClear(.fors_tree);
    a.setKeyPair(0x21222324);
    a.setTreeHeight(0x31323334);
    a.setTreeIndex(0x41424344);
    const b = a.bytes;
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, b[0..4]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, b[4..8]);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 },
        b[8..16],
    );
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 3 }, b[16..20]);
    try std.testing.expectEqual(@as(u32, 0x21222324), a.getKeyPair());
    try std.testing.expectEqual(@as(u32, 0x41424344), a.getTreeIndex());
}

test "setTypeAndClear zeroes the trailing words" {
    var a: Address = .{};
    a.setKeyPair(7);
    a.setChain(9);
    a.setHash(11);
    a.setTypeAndClear(.wots_prf);
    try std.testing.expectEqualSlices(u8, &(@as([12]u8, @splat(0))), a.bytes[20..32]);
}

test "compressed drops exactly the SHA2 padding bytes" {
    var a: Address = .{};
    a.setLayer(0xAA);
    a.setTree(0x0102030405060708);
    a.setTypeAndClear(.tree);
    a.setTreeHeight(2);
    a.setTreeIndex(5);
    const c = a.compressed();
    try std.testing.expectEqual(@as(u8, 0xAA), c[0]);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        c[1..9],
    );
    try std.testing.expectEqual(@as(u8, 2), c[9]); // type byte
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 5 },
        c[10..22],
    );
}
