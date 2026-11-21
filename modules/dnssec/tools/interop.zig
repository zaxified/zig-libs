// SPDX-License-Identifier: MIT

//! Foreign check of `dnssec.sign`: zones signed here (RSASHA256, RSASHA512, ECDSAP256SHA256, ECDSAP384SHA384, ED25519, ED448;
//! SOA, NS, A, DNSKEY and an NSEC chain, every RRset with its RRSIG) must be accepted by NLnet Labs'
//! `ldns-verify-zone` (BSD-3-Clause, run as a black box), and the same zone with one A record changed must be
//! refused.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-dnssec` runs it and `zig build check-interop` compiles it.
//! Needs `ldns-verify-zone` (package `ldnsutils`) on PATH; if it is missing the program says so and exits 2. No
//! network. Run from the repository root; the zones go to `.zig-cache/interop-dnssec/`. Exit 0 = every zone was
//! accepted and every tampered zone refused.

const std = @import("std");
const dnssec = @import("dnssec");
const dns = @import("dns");
const rsa = @import("rsa");
const ed448 = @import("ed448").ed448;

const work_dir = ".zig-cache/interop-dnssec";
const origin = "example.org";
const inception: u32 = 1_700_000_000; // 2023-11-14
const expiration: u32 = 2_000_000_000; // 2033-05-18
const verify_time = "20260101000000";

const Ed25519 = std.crypto.sign.Ed25519;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const Keys = struct {
    rsa_kp: rsa.KeyPair,
    rsa_pub: []const u8,
    p256: P256.KeyPair,
    p384: P384.KeyPair,
    ed: Ed25519.KeyPair,
    ed448: ed448.KeyPair,
};

const Case = struct {
    name: []const u8,
    algorithm: u8,
    key: dnssec.sign.SigningKey,
    public_key: []const u8,
};

fn hex(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    return arena.print("{x}", .{bytes});
}

fn nameWire(arena: std.mem.Allocator, name: []const u8) ![]u8 {
    var buf: [dnssec.wire.max_canonical_wire_len]u8 = undefined;
    return arena.dupe(u8, try dnssec.wire.encodeCanonicalName(name, &buf));
}

fn bitmap(arena: std.mem.Allocator, types: []const u16) ![]u8 {
    var bits: [32]u8 = @splat(0);
    var top: usize = 0;
    for (types) |t| {
        bits[t / 8] |= @as(u8, 0x80) >> @intCast(t % 8);
        top = @max(top, t / 8 + 1);
    }
    const out = try arena.alloc(u8, 2 + top);
    out[0] = 0;
    out[1] = @intCast(top);
    @memcpy(out[2..], bits[0..top]);
    return out;
}

const Zone = struct {
    arena: std.mem.Allocator,
    c: Case,
    tag: u16,
    text: std.ArrayList(u8) = .empty,

    /// Emit `records` (one RRset) in RFC 3597 generic presentation, then its RRSIG.
    fn rrset(z: *Zone, owner: []const u8, type_name: []const u8, recs: []const dns.Record) !void {
        for (recs) |r| {
            const raw = switch (r.data) {
                .unknown => |u| u,
                .a => |a| try z.arena.dupe(u8, &a),
                else => unreachable,
            };
            try z.text.print(z.arena, "{s}. {d} IN {s} \\# {d} {s}\n", .{ owner, r.ttl, type_name, raw.len, try hex(z.arena, raw) });
        }
        const sig = try dnssec.sign.signRrset(z.arena, recs, owner, z.c.key, .{
            .signer_name = origin,
            .key_tag = z.tag,
            .inception = inception,
            .expiration = expiration,
        });
        try z.text.print(z.arena, "{s}. {d} IN RRSIG \\# {d} {s}\n", .{ owner, recs[0].ttl, sig.len, try hex(z.arena, sig) });
    }
};

fn rec(owner: []const u8, ty: u16, ttl: u32, raw: []const u8) dns.Record {
    return .{ .name = owner, .ty = @fromBackingInt(@intCast(ty)), .class = .in, .ttl = ttl, .data = .{ .unknown = raw } };
}

fn buildZone(arena: std.mem.Allocator, c: Case) ![]const u8 {
    const dnskey = try dnssec.sign.encodeDnskey(arena, 0x0101, c.algorithm, c.public_key);
    var z: Zone = .{ .arena = arena, .c = c, .tag = dnssec.rdata.keyTag(dnskey, c.algorithm) };
    const ns = "ns." ++ origin;
    const www = "www." ++ origin;

    var soa: std.ArrayList(u8) = .empty;
    try soa.appendSlice(arena, try nameWire(arena, ns));
    try soa.appendSlice(arena, try nameWire(arena, "hostmaster." ++ origin));
    for ([_]u32{ 2026010101, 7200, 3600, 1209600, 3600 }) |v| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .big);
        try soa.appendSlice(arena, &b);
    }
    try z.rrset(origin, "SOA", &.{rec(origin, 6, 3600, soa.items)});
    try z.rrset(origin, "NS", &.{rec(origin, 2, 3600, try nameWire(arena, ns))});
    try z.rrset(origin, "DNSKEY", &.{rec(origin, 48, 3600, dnskey)});
    try z.rrset(ns, "A", &.{.{ .name = ns, .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, 53 } } }});
    try z.rrset(www, "A", &.{
        .{ .name = www, .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, 1 } } },
        .{ .name = www, .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, 2 } } },
    });
    // NSEC chain apex -> ns -> www -> apex.
    try z.rrset(origin, "NSEC", &.{rec(origin, 47, 3600, try nsecRdata(arena, ns, &.{ 2, 6, 46, 47, 48 }))});
    try z.rrset(ns, "NSEC", &.{rec(ns, 47, 3600, try nsecRdata(arena, www, &.{ 1, 46, 47 }))});
    try z.rrset(www, "NSEC", &.{rec(www, 47, 3600, try nsecRdata(arena, origin, &.{ 1, 46, 47 }))});
    return z.text.items;
}

fn nsecRdata(arena: std.mem.Allocator, next: []const u8, types: []const u16) ![]u8 {
    return std.mem.concat(arena, u8, &.{ try nameWire(arena, next), try bitmap(arena, types) });
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);

    const probe = std.process.run(arena, io, .{ .argv = &.{ "ldns-verify-zone", "-v" } }) catch {
        std.debug.print("interop-dnssec: ldns-verify-zone not found (package ldnsutils)\n", .{});
        return 2;
    };
    std.debug.print("interop-dnssec: {s}", .{probe.stdout});

    var prng = std.Random.DefaultCsprng.init(@as([32]u8, @splat(0x5a)));
    var keys: Keys = undefined;
    try rsa.generate(&keys.rsa_kp, prng.random(), 1024, 65537);
    var nbuf: [128]u8 = undefined;
    try keys.rsa_kp.public_key.n.toBytes(&nbuf, .big);
    keys.rsa_pub = try dnssec.sign.encodeRsaPublicKey(arena, &.{ 0x01, 0x00, 0x01 }, &nbuf);
    keys.p256 = try P256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x21)));
    keys.p384 = try P384.KeyPair.generateDeterministic(@as([48]u8, @splat(0x22)));
    keys.ed = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x23)));
    keys.ed448 = ed448.KeyPair.create(&@as([57]u8, @splat(0x24)));

    const cases = [_]Case{
        .{ .name = "rsasha256", .algorithm = 8, .key = .{ .rsa_sha256 = &keys.rsa_kp.secret_key }, .public_key = keys.rsa_pub },
        .{ .name = "rsasha512", .algorithm = 10, .key = .{ .rsa_sha512 = &keys.rsa_kp.secret_key }, .public_key = keys.rsa_pub },
        .{ .name = "ecdsap256", .algorithm = 13, .key = .{ .ecdsa_p256 = &keys.p256 }, .public_key = keys.p256.public_key.toUncompressedSec1()[1..] },
        .{ .name = "ecdsap384", .algorithm = 14, .key = .{ .ecdsa_p384 = &keys.p384 }, .public_key = keys.p384.public_key.toUncompressedSec1()[1..] },
        .{ .name = "ed25519", .algorithm = 15, .key = .{ .ed25519 = &keys.ed }, .public_key = &keys.ed.public_key.toBytes() },
        .{ .name = "ed448", .algorithm = 16, .key = .{ .ed448 = &keys.ed448 }, .public_key = &keys.ed448.public_key.toBytes() },
    };

    var failures: usize = 0;
    for (cases) |c| {
        for ([_]bool{ false, true }) |tamper| {
            // For `tamper` one A record of the signed zone is changed in the text, so the RRSIG no longer covers it.
            const good = try buildZone(arena, c);
            const text = if (tamper) try buildTampered(arena, good) else good;
            const path = try arena.print("{s}/{s}{s}.zone", .{ work_dir, c.name, if (tamper) "-tampered" else "" });
            try cwd.writeFile(io, .{ .sub_path = path, .data = text });
            const res = try std.process.run(arena, io, .{ .argv = &.{ "ldns-verify-zone", "-t", verify_time, path } });
            const accepted = res.term == .exited and res.term.exited == 0;
            const ok = accepted != tamper;
            std.debug.print("interop-dnssec: {s}{s}: ldns-verify-zone {s} -> {s}\n", .{ c.name, if (tamper) " (tampered)" else "", if (accepted) "accepted" else "refused", if (ok) "ok" else "UNEXPECTED" });
            if (!ok) {
                failures += 1;
                std.debug.print("{s}{s}\n", .{ res.stdout, res.stderr });
            }
        }
    }
    return if (failures == 0) 0 else 1;
}

/// The signed zone with the second A record of www changed in the text only (RRSIGs untouched).
fn buildTampered(arena: std.mem.Allocator, good: []const u8) ![]const u8 {
    // The A record 192.0.2.2 = c0000202; the tampered data is c0000203.
    const needle = "\\# 4 c0000202";
    const at = std.mem.find(u8, good, needle) orelse return error.NoNeedle;
    const out = try arena.dupe(u8, good);
    out[at + needle.len - 1] = '3';
    return out;
}
