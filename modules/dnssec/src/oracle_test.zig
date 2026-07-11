// SPDX-License-Identifier: MIT

//! Known-answer tests for the DNSSEC validation core against REAL signed
//! zones. The vectors in `oracle_vectors.zig` are extracted from zones signed
//! by `ldns-signzone` across algorithms 8/13/14/15 (RSA-SHA256, ECDSA-P256,
//! ECDSA-P384, Ed25519), with NSEC, NSEC3 and NSEC3 Opt-Out, plus a wildcard.
//! Each source zone was independently accepted by `ldns-verify-zone`.
//!
//! A valid RRSIG signature only verifies over byte-exact RFC 4034 §3.1.8.1
//! canonical data, so `validate`/`chain` returning `.secure` on these vectors
//! IS the proof that `canonical.buildSignedData` is byte-correct — including
//! canonical RR ordering, original-TTL substitution, embedded-name lowering,
//! and wildcard-name substitution. Tampering (a flipped signature/digest
//! byte) must yield `.bogus`.

const std = @import("std");
const testing = std.testing;
const dns = @import("dns");

const root = @import("root.zig");
const rdata = @import("rdata.zig");
const chain = @import("chain.zig");
const nsec3 = @import("nsec3.zig");
const vectors = @import("oracle_vectors.zig");

const ty_a: u16 = 1;
const ty_ns: u16 = 2;
const ty_soa: u16 = 6;
const ty_mx: u16 = 15;
const ty_txt: u16 = 16;
const ty_nsec: u16 = 47;
const ty_dnskey: u16 = 48;

fn recordsFrom(a: std.mem.Allocator, v: vectors.Vec) ![]dns.Record {
    const recs = try a.alloc(dns.Record, v.records.len);
    for (v.records, 0..) |raw, i| recs[i] = .{
        .name = v.name,
        .ty = @enumFromInt(v.ty),
        .class = .in,
        .ttl = 999, // deliberately NOT the signed original_ttl — must be ignored
        .data = .{ .unknown = raw },
    };
    return recs;
}

test "oracle: every RRset verifies Secure under a pinned DNSKEY (all algorithms/types)" {
    for (vectors.verify_vecs) |v| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const rrsig = try rdata.parseRrsig(a, v.rrsig_rdata);
        const dnskey = try rdata.parseDnskey(v.key_rdata);
        const recs = try recordsFrom(a, v);
        const anchor: chain.TrustAnchor = .{ .dnskey_rdata = v.key_rdata };

        const res = try root.validate(testing.allocator, recs, rrsig, v.name, dnskey, anchor, .{ .now = rrsig.inception });
        testing.expectEqual(root.ValidationResult.secure, res) catch |e| {
            std.debug.print("FAIL secure: alg={d} ty={d} name={s}\n", .{ v.alg, v.ty, v.name });
            return e;
        };
    }
}

test "oracle: a single flipped signature byte turns every RRset Bogus" {
    for (vectors.verify_vecs) |v| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();

        var rrsig = try rdata.parseRrsig(a, v.rrsig_rdata);
        const sig = try a.dupe(u8, rrsig.signature);
        sig[sig.len - 1] ^= 0x01;
        rrsig.signature = sig;

        const dnskey = try rdata.parseDnskey(v.key_rdata);
        const recs = try recordsFrom(a, v);
        const anchor: chain.TrustAnchor = .{ .dnskey_rdata = v.key_rdata };

        const res = try root.validate(testing.allocator, recs, rrsig, v.name, dnskey, anchor, .{ .now = rrsig.inception });
        try testing.expectEqual(root.ValidationResult.bogus, res);
    }
}

test "oracle: RRSIG outside its validity window is Bogus" {
    const v = vectors.verify_vecs[0];
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rrsig = try rdata.parseRrsig(a, v.rrsig_rdata);
    const dnskey = try rdata.parseDnskey(v.key_rdata);
    const recs = try recordsFrom(a, v);
    const anchor: chain.TrustAnchor = .{ .dnskey_rdata = v.key_rdata };
    // one second past expiration
    const res = try root.validate(testing.allocator, recs, rrsig, v.name, dnskey, anchor, .{ .now = rrsig.expiration +% 1 });
    try testing.expectEqual(root.ValidationResult.bogus, res);
}

test "oracle: wildcard expansion — RRSIG.labels substitution verifies Secure" {
    const v = vectors.wildcard;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rrsig = try rdata.parseRrsig(a, v.rrsig_rdata);
    try testing.expect(rrsig.labels == 1); // *.example, signed under an expanded owner
    const dnskey = try rdata.parseDnskey(v.key_rdata);
    const recs = try recordsFrom(a, v);
    const anchor: chain.TrustAnchor = .{ .dnskey_rdata = v.key_rdata };
    const res = try root.validate(testing.allocator, recs, rrsig, v.name, dnskey, anchor, .{ .now = rrsig.inception });
    try testing.expectEqual(root.ValidationResult.secure, res);
}

// ── typed-record canonicalization (exercises canonicalRdata, not passthrough) ──

fn findVec(alg: u8, ty: u16) vectors.Vec {
    for (vectors.verify_vecs) |v| {
        if (v.alg == alg and v.ty == ty) return v;
    }
    unreachable;
}

fn expectTypedSecure(recs: []const dns.Record, ty: u16, alg: u8) !void {
    const v = findVec(alg, ty);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const rrsig = try rdata.parseRrsig(arena.allocator(), v.rrsig_rdata);
    const dnskey = try rdata.parseDnskey(v.key_rdata);
    const anchor: chain.TrustAnchor = .{ .dnskey_rdata = v.key_rdata };
    const res = try root.validate(testing.allocator, recs, rrsig, v.name, dnskey, anchor, .{ .now = rrsig.inception });
    try testing.expectEqual(root.ValidationResult.secure, res);
}

test "oracle: typed SOA/MX/NS/A records canonicalize byte-exact (alg 13)" {
    // SOA: two embedded names + five u32s (from the zone's SOA).
    const soa = [_]dns.Record{.{
        .name = "example",
        .ty = @enumFromInt(ty_soa),
        .class = .in,
        .ttl = 1,
        .data = .{ .soa = .{
            .mname = "ns1.example",
            .rname = "admin.example",
            .serial = 2026070101,
            .refresh = 7200,
            .retry = 3600,
            .expire = 1209600,
            .minimum = 3600,
        } },
    }};
    try expectTypedSecure(&soa, ty_soa, 13);

    // MX: preference + embedded exchange name.
    const mx = [_]dns.Record{.{
        .name = "example",
        .ty = @enumFromInt(ty_mx),
        .class = .in,
        .ttl = 1,
        .data = .{ .mx = .{ .preference = 10, .exchange = "mail.example" } },
    }};
    try expectTypedSecure(&mx, ty_mx, 13);

    // NS: two records — exercises canonical RR ordering of embedded names.
    const ns = [_]dns.Record{
        .{ .name = "example", .ty = @enumFromInt(ty_ns), .class = .in, .ttl = 1, .data = .{ .ns = "ns2.example" } },
        .{ .name = "example", .ty = @enumFromInt(ty_ns), .class = .in, .ttl = 1, .data = .{ .ns = "ns1.example" } },
    };
    try expectTypedSecure(&ns, ty_ns, 13);

    // A: www 192.0.2.80.
    const a4 = [_]dns.Record{.{
        .name = "www.example",
        .ty = @enumFromInt(ty_a),
        .class = .in,
        .ttl = 1,
        .data = .{ .a = .{ 192, 0, 2, 80 } },
    }};
    try expectTypedSecure(&a4, ty_a, 13);
}

// ── chain: DS → DNSKEY delegation link (all algorithms) ────────────────────

test "oracle: DNSKEY set validates Secure against a parent DS (all algorithms)" {
    for (vectors.ds_vecs) |d| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const dnskey_vec = findVec(d.alg, ty_dnskey);
        const rrsig = try rdata.parseRrsig(a, dnskey_vec.rrsig_rdata);
        const ds = try rdata.parseDs(d.ds_rdata);

        const res = try chain.validateDnskeySet(testing.allocator, "example", dnskey_vec.records, rrsig, .{ .ds = ds });
        testing.expectEqual(chain.ChainResult.secure, res) catch |e| {
            std.debug.print("FAIL chain secure: alg={d}\n", .{d.alg});
            return e;
        };
    }
}

test "oracle: DS with a tampered digest -> Bogus (no matching DNSKEY)" {
    const d = vectors.ds_vecs[0];
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dnskey_vec = findVec(d.alg, ty_dnskey);
    const rrsig = try rdata.parseRrsig(a, dnskey_vec.rrsig_rdata);

    const bad = try a.dupe(u8, d.ds_rdata);
    bad[bad.len - 1] ^= 0xff; // corrupt the digest
    const ds = try rdata.parseDs(bad);
    const res = try chain.validateDnskeySet(testing.allocator, "example", dnskey_vec.records, rrsig, .{ .ds = ds });
    try testing.expectEqual(chain.ChainResult.bogus, res);
}

test "oracle: DNSKEY self-signature tampered -> Bogus (DS matches but no valid sig)" {
    const d = vectors.ds_vecs[1];
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dnskey_vec = findVec(d.alg, ty_dnskey);
    var rrsig = try rdata.parseRrsig(a, dnskey_vec.rrsig_rdata);
    const sig = try a.dupe(u8, rrsig.signature);
    sig[sig.len - 1] ^= 0x01;
    rrsig.signature = sig;
    const ds = try rdata.parseDs(d.ds_rdata);
    const res = try chain.validateDnskeySet(testing.allocator, "example", dnskey_vec.records, rrsig, .{ .ds = ds });
    try testing.expectEqual(chain.ChainResult.bogus, res);
}

// ── NSEC3 denial of existence (RFC 5155 §8) ────────────────────────────────

fn nsec3Set(a: std.mem.Allocator, entries: []const vectors.Nsec3Entry) ![]nsec3.Nsec3Record {
    const out = try a.alloc(nsec3.Nsec3Record, entries.len);
    for (entries, 0..) |e, i| {
        out[i] = .{ .owner_hash_label = e.label, .rdata = try rdata.parseNsec3(e.rdata) };
    }
    return out;
}

test "oracle: NSEC3 NODATA — existing name, absent type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const set = try nsec3Set(arena.allocator(), &vectors.nsec3);
    // existing.example has an A but no TXT -> NODATA.
    const r = nsec3.proveDenial("existing.example", ty_txt, .{ .records = set }, vectors.nsec3_salt, vectors.nsec3_iterations);
    try testing.expectEqual(nsec3.DenialResult.no_data, r);
}

test "oracle: NSEC3 NXDOMAIN — closest encloser + next closer + wildcard cover" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const set = try nsec3Set(arena.allocator(), &vectors.nsec3);
    // sub.www.example: closest encloser www.example, no *.www.example -> NXDOMAIN.
    const r = nsec3.proveDenial("sub.www.example", ty_a, .{ .records = set }, vectors.nsec3_salt, vectors.nsec3_iterations);
    try testing.expectEqual(nsec3.DenialResult.name_error, r);
}

test "oracle: NSEC3 wildcard answer — name matches the *.example wildcard for A" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const set = try nsec3Set(arena.allocator(), &vectors.nsec3);
    const r = nsec3.proveDenial("nonexist.example", ty_a, .{ .records = set }, vectors.nsec3_salt, vectors.nsec3_iterations);
    try testing.expectEqual(nsec3.DenialResult.wildcard_answer, r);
}

test "oracle: NSEC3 wildcard NODATA — wildcard exists but lacks the queried type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const set = try nsec3Set(arena.allocator(), &vectors.nsec3);
    // *.example has A only; a query for MX under a wildcard-covered name -> NODATA.
    const r = nsec3.proveDenial("nonexist.example", ty_mx, .{ .records = set }, vectors.nsec3_salt, vectors.nsec3_iterations);
    try testing.expectEqual(nsec3.DenialResult.no_data, r);
}

test "oracle: NSEC3 Opt-Out — NXDOMAIN over an opt-out span downgrades to Insecure" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const set = try nsec3Set(arena.allocator(), &vectors.nsec3opt);
    const r = nsec3.proveDenial("sub.www.example", ty_a, .{ .records = set }, vectors.nsec3opt_salt, vectors.nsec3opt_iterations);
    try testing.expectEqual(nsec3.DenialResult.insecure, r);
}
