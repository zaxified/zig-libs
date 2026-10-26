// SPDX-License-Identifier: MIT
//! Test-only certificate writer: ECDSA P-256 chains with chosen extensions,
//! validity and signature algorithm, built in the test instead of committed
//! as DER (fixed-seed keys, std's deterministic signatures). The same DER
//! writer as `tools/interop.zig`, cut down to what the tests use.

const std = @import("std");

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// 2025-01-01 and 2035-01-01: the default validity window.
pub const t_nb: i64 = 1735689600;
pub const t_na: i64 = 2051222400;
/// 2026-06-01, inside every default window.
pub const t_now: i64 = 1780272000;

pub fn key(seed_byte: u8) Ecdsa.KeyPair {
    return Ecdsa.KeyPair.generateDeterministic(@splat(seed_byte)) catch unreachable;
}

pub const Gen = struct {
    a: std.mem.Allocator,
    serial: u32 = 0x100,

    pub fn tlv(g: *Gen, tag: u8, parts: []const []const u8) ![]const u8 {
        var n: usize = 0;
        for (parts) |p| n += p.len;
        var out: std.ArrayList(u8) = .empty;
        try out.append(g.a, tag);
        if (n < 0x80) {
            try out.append(g.a, @intCast(n));
        } else if (n < 0x100) {
            try out.appendSlice(g.a, &.{ 0x81, @intCast(n) });
        } else {
            try out.appendSlice(g.a, &.{ 0x82, @intCast(n >> 8), @truncate(n) });
        }
        for (parts) |p| try out.appendSlice(g.a, p);
        return out.items;
    }

    pub fn seq(g: *Gen, parts: []const []const u8) ![]const u8 {
        return g.tlv(0x30, parts);
    }

    fn int(g: *Gen, v: u32) ![]const u8 {
        var be: [5]u8 = undefined;
        be[0] = 0;
        std.mem.writeInt(u32, be[1..5], v, .big);
        var i: usize = 0;
        while (i < 4 and be[i] == 0 and be[i + 1] & 0x80 == 0) i += 1;
        return g.tlv(0x02, &.{be[i..]});
    }

    fn utcTime(g: *Gen, unix: i64) ![]const u8 {
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix) };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        var buf: [13]u8 = undefined;
        const s = try std.mem.print(&buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            yd.year % 100,        md.month.numeric(),      md.day_index + 1,
            ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        });
        return g.tlv(0x17, &.{s});
    }

    /// A Name with one RDN: CN=`cn`.
    pub fn name(g: *Gen, cn: []const u8) ![]const u8 {
        const atv = try g.seq(&.{ try g.tlv(0x06, &.{&.{ 0x55, 0x04, 0x03 }}), try g.tlv(0x0c, &.{cn}) });
        return g.seq(&.{try g.tlv(0x31, &.{atv})});
    }

    pub fn extension(g: *Gen, oid: []const u8, critical: bool, value: []const u8) ![]const u8 {
        if (critical) return g.seq(&.{ try g.tlv(0x06, &.{oid}), try g.tlv(0x01, &.{&.{0xff}}), try g.tlv(0x04, &.{value}) });
        return g.seq(&.{ try g.tlv(0x06, &.{oid}), try g.tlv(0x04, &.{value}) });
    }

    /// basicConstraints cA TRUE [pathLenConstraint].
    pub fn extCa(g: *Gen, path_len: ?u32) ![]const u8 {
        var parts: std.ArrayList([]const u8) = .empty;
        try parts.append(g.a, try g.tlv(0x01, &.{&.{0xff}}));
        if (path_len) |n| try parts.append(g.a, try g.int(n));
        return g.extension(&.{ 0x55, 0x1d, 0x13 }, true, try g.seq(parts.items));
    }

    /// keyUsage keyCertSign + cRLSign.
    pub fn extKuCa(g: *Gen) ![]const u8 {
        return g.extension(&.{ 0x55, 0x1d, 0x0f }, true, try g.tlv(0x03, &.{&.{ 0x01, 0x06 }}));
    }

    /// keyUsage digitalSignature.
    pub fn extKuLeaf(g: *Gen) ![]const u8 {
        return g.extension(&.{ 0x55, 0x1d, 0x0f }, true, try g.tlv(0x03, &.{&.{ 0x07, 0x80 }}));
    }

    /// subjectAltName with one dNSName.
    pub fn extSanDns(g: *Gen, dns: []const u8) ![]const u8 {
        return g.extension(&.{ 0x55, 0x1d, 0x11 }, false, try g.seq(&.{try g.tlv(0x82, &.{dns})}));
    }

    /// nameConstraints with one excluded dNSName subtree.
    pub fn extNcExcludedDns(g: *Gen, dns: []const u8) ![]const u8 {
        const subtree = try g.seq(&.{try g.tlv(0x82, &.{dns})});
        return g.extension(&.{ 0x55, 0x1d, 0x1e }, true, try g.seq(&.{try g.tlv(0xa1, &.{subtree})}));
    }

    pub const Spec = struct {
        subject: []const u8,
        issuer: []const u8,
        key: *const Ecdsa.KeyPair,
        signer: *const Ecdsa.KeyPair,
        exts: []const []const u8,
        nb: i64 = t_nb,
        na: i64 = t_na,
        /// The whole AlgorithmIdentifier, in place of ecdsa-with-SHA256 (the
        /// signature is still ECDSA P-256 over SHA-256).
        sig_alg: ?[]const u8 = null,
    };

    pub fn cert(g: *Gen, s: Spec) ![]const u8 {
        g.serial += 1;
        const alg = s.sig_alg orelse try g.seq(&.{try g.tlv(0x06, &.{&.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 }})});
        const point = s.key.public_key.toUncompressedSec1();
        const spki = try g.seq(&.{
            try g.seq(&.{
                try g.tlv(0x06, &.{&.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }}),
                try g.tlv(0x06, &.{&.{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }}),
            }),
            try g.tlv(0x03, &.{ &.{0x00}, &point }),
        });
        var parts: std.ArrayList([]const u8) = .empty;
        try parts.appendSlice(g.a, &.{
            try g.tlv(0xa0, &.{try g.int(2)}),
            try g.int(g.serial),
            alg,
            s.issuer,
            try g.seq(&.{ try g.utcTime(s.nb), try g.utcTime(s.na) }),
            s.subject,
            spki,
        });
        if (s.exts.len != 0) try parts.append(g.a, try g.tlv(0xa3, &.{try g.seq(s.exts)}));
        const tbs = try g.seq(parts.items);
        const sig = try s.signer.sign(tbs, null);
        var sig_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        return g.seq(&.{ tbs, alg, try g.tlv(0x03, &.{ &.{0x00}, sig.toDer(&sig_buf) }) });
    }
};
