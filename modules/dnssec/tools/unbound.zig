// SPDX-License-Identifier: MIT

//! `dnssec.walk` against a foreign validating resolver. A signed hierarchy built with `dnssec.sign` (root, `lab`,
//! `example.lab`, Ed25519; an unsigned delegation `insecure.lab`) is served two ways: as `auth-zone` files to NLnet
//! Labs' libunbound (`unbound-host -v`, BSD-3-Clause, a black box, network namespace without interfaces so nothing is
//! asked of the real DNS), and as RRsets to `walk.validateRrset` through a `Fetcher`. For each scenario (secure,
//! insecure delegation, an altered A record, a DS made from another key) the two verdicts must agree.
//! Called from `interop.zig`; skipped (not a failure) when `unbound-host` or `unshare` is missing.

const std = @import("std");
const dnssec = @import("dnssec");
const dns = @import("dns");

const work_dir = ".zig-cache/interop-dnssec";
const Ed25519 = std.crypto.sign.Ed25519;
const rdata = dnssec.rdata;

// The RRSIG window of every signature (unbound reads the clock, `now` below sits inside it).
const inception: u32 = 1_700_000_000;
const expiration: u32 = 2_000_000_000;
const now: u32 = 1_795_000_000;

const Zone = struct {
    name: []const u8,
    kp: Ed25519.KeyPair,
    dnskey: []const u8,
    tag: u16,
    text: std.ArrayList(u8) = .empty,
};

const Verdict = enum { secure, insecure, bogus };

const Set = struct { owner: []const u8, ty: u16, rrset: dnssec.walk.Rrset };

const World = struct {
    arena: std.mem.Allocator,
    sets: std.ArrayList(Set) = .empty,
    /// `owner`, `ty` -> the response the walker asks for (a DS query answered by NSEC lives under type 43).
    answers: std.ArrayList(Set) = .empty,
    /// The next `put` signs these RDATA instead of the published ones (a record altered after signing).
    sign_raws: ?[]const []const u8 = null,

    fn fetch(ctx: *anyopaque, name: []const u8, ty: u16) dnssec.walk.FetchError![]const dnssec.walk.Rrset {
        const w: *World = @ptrCast(@alignCast(ctx));
        for (w.answers.items) |*s| {
            if (s.ty == ty and std.ascii.eqlIgnoreCase(s.owner, name)) return @as([*]const dnssec.walk.Rrset, @ptrCast(&s.rrset))[0..1];
        }
        return &.{};
    }
};

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

fn nsecRdata(arena: std.mem.Allocator, next: []const u8, types: []const u16) ![]u8 {
    return std.mem.concat(arena, u8, &.{ try nameWire(arena, next), try bitmap(arena, types) });
}

fn soaRdata(arena: std.mem.Allocator, zone: []const u8) ![]u8 {
    var soa: std.ArrayList(u8) = .empty;
    try soa.appendSlice(arena, try nameWire(arena, try nameOf(arena, "ns", zone)));
    try soa.appendSlice(arena, try nameWire(arena, try nameOf(arena, "hostmaster", zone)));
    for ([_]u32{ 2026010101, 7200, 3600, 1209600, 3600 }) |v| {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .big);
        try soa.appendSlice(arena, &b);
    }
    return soa.items;
}

/// `label` under `zone` ("" is the root).
fn nameOf(arena: std.mem.Allocator, label: []const u8, zone: []const u8) ![]const u8 {
    return if (zone.len == 0) label else arena.print("{s}.{s}", .{ label, zone });
}

fn typeName(ty: u16) []const u8 {
    return switch (ty) {
        1 => "A",
        2 => "NS",
        6 => "SOA",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        else => unreachable,
    };
}

fn presentOwner(arena: std.mem.Allocator, owner: []const u8) ![]const u8 {
    return if (owner.len == 0) arena.dupe(u8, ".") else arena.print("{s}.", .{owner});
}

fn records(arena: std.mem.Allocator, owner: []const u8, ty: u16, raws: []const []const u8) ![]dns.Record {
    const recs = try arena.alloc(dns.Record, raws.len);
    for (raws, recs) |raw, *r| {
        const data: @FieldType(dns.Record, "data") = if (ty == 1) .{ .a = raw[0..4].* } else .{ .unknown = raw };
        r.* = .{ .name = owner, .ty = @fromBackingInt(@intCast(ty)), .class = .in, .ttl = 3600, .data = data };
    }
    return recs;
}

/// One RRset into the zone text: its records, and, when `signer` is given, its RRSIG (also recorded for the walker
/// under the query `answer_ty`: the type that is asked for, which differs from `ty` for an NSEC answering a DS query).
fn put(w: *World, z: *Zone, owner: []const u8, ty: u16, raws: []const []const u8, signer: ?*const Zone, answer_ty: ?u16) !void {
    const arena = w.arena;
    const recs = try records(arena, owner, ty, raws);
    const owner_text = try presentOwner(arena, owner);
    for (raws) |raw| try z.text.print(arena, "{s} 3600 IN {s} \\# {d} {x}\n", .{ owner_text, typeName(ty), raw.len, raw });
    var sigs: []const []const u8 = &.{};
    if (signer) |s| {
        const signed = if (w.sign_raws) |sr| try records(arena, owner, ty, sr) else recs;
        w.sign_raws = null;
        const sig = try dnssec.sign.signRrset(arena, signed, owner, .{ .ed25519 = &s.kp }, .{
            .signer_name = s.name,
            .key_tag = s.tag,
            .inception = inception,
            .expiration = expiration,
        });
        try z.text.print(arena, "{s} 3600 IN RRSIG \\# {d} {x}\n", .{ owner_text, sig.len, sig });
        sigs = try arena.dupe([]const u8, &.{sig});
    }
    const set: Set = .{ .owner = owner, .ty = ty, .rrset = .{ .records = recs, .rrsigs = sigs } };
    try w.sets.append(arena, set);
    try w.answers.append(arena, .{ .owner = owner, .ty = answer_ty orelse ty, .rrset = set.rrset });
}

fn newZone(arena: std.mem.Allocator, name: []const u8, seed: u8) !Zone {
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
    const dk = try dnssec.sign.encodeDnskey(arena, 0x0101, rdata.algorithm.ed25519, &kp.public_key.toBytes());
    return .{ .name = name, .kp = kp, .dnskey = dk, .tag = rdata.keyTag(dk, rdata.algorithm.ed25519) };
}

const Scenario = struct { name: []const u8, qname: []const u8, want: Verdict, alter_a: bool = false, wrong_ds: bool = false };

const scenarios = [_]Scenario{
    .{ .name = "secure", .qname = "www.example.lab", .want = .secure },
    .{ .name = "insecure delegation", .qname = "www.insecure.lab", .want = .insecure },
    .{ .name = "altered A record", .qname = "www.example.lab", .want = .bogus, .alter_a = true },
    .{ .name = "DS of another key", .qname = "www.example.lab", .want = .bogus, .wrong_ds = true },
};

/// The hierarchy for one scenario: the three zone texts (root, test, example.lab), the unsigned zone, the walker's
/// answers and the root DNSKEY (the trust anchor).
fn build(w: *World, sc: Scenario, root_text: *Zone, test_text: *Zone, ex_text: *Zone, insecure_text: *std.ArrayList(u8)) !void {
    const a = w.arena;
    const ns_a = [_][]const u8{&.{ 192, 0, 2, 53 }};
    // The zone keys do not depend on the scenario, the DS of example.lab may.
    var rz = root_text.*;
    var tz = test_text.*;
    var ez = ex_text.*;
    const other = try newZone(a, "example.lab", 9);

    // root: apex, ns, the cut to test.
    try put(w, &rz, "", 6, &.{try soaRdata(a, "")}, &rz, null);
    try put(w, &rz, "", 2, &.{try nameWire(a, "ns")}, &rz, null);
    try put(w, &rz, "", 48, &.{rz.dnskey}, &rz, null);
    try put(w, &rz, "ns", 1, &ns_a, &rz, null);
    try put(w, &rz, "lab", 2, &.{try nameWire(a, "ns.lab")}, null, null);
    const test_ds = try dnssec.sign.encodeDs(a, "lab", tz.dnskey, rdata.Ds.digest_sha256);
    try put(w, &rz, "lab", 43, &.{test_ds}, &rz, null);
    try put(w, &rz, "", 47, &.{try nsecRdata(a, "ns", &.{ 2, 6, 46, 47, 48 })}, &rz, null);
    try put(w, &rz, "ns", 47, &.{try nsecRdata(a, "lab", &.{ 1, 46, 47 })}, &rz, null);
    try put(w, &rz, "lab", 47, &.{try nsecRdata(a, "", &.{ 2, 43, 46, 47 })}, &rz, null);

    // test: apex, ns, the cut to example.lab (signed), the cut to insecure.lab (unsigned).
    try put(w, &tz, "lab", 6, &.{try soaRdata(a, "lab")}, &tz, null);
    try put(w, &tz, "lab", 2, &.{try nameWire(a, "ns.lab")}, &tz, null);
    try put(w, &tz, "lab", 48, &.{tz.dnskey}, &tz, null);
    try put(w, &tz, "ns.lab", 1, &ns_a, &tz, null);
    try put(w, &tz, "example.lab", 2, &.{try nameWire(a, "ns.example.lab")}, null, null);
    const ex_ds = try dnssec.sign.encodeDs(a, "example.lab", if (sc.wrong_ds) other.dnskey else ez.dnskey, rdata.Ds.digest_sha256);
    try put(w, &tz, "example.lab", 43, &.{ex_ds}, &tz, null);
    try put(w, &tz, "insecure.lab", 2, &.{try nameWire(a, "ns.insecure.lab")}, null, null);
    try put(w, &tz, "lab", 47, &.{try nsecRdata(a, "example.lab", &.{ 2, 6, 46, 47, 48 })}, &tz, null);
    try put(w, &tz, "example.lab", 47, &.{try nsecRdata(a, "insecure.lab", &.{ 2, 43, 46, 47 })}, &tz, null);
    // insecure.lab: a delegation without DS: its NSEC, signed by the parent, answers the DS query.
    try put(w, &tz, "insecure.lab", 47, &.{try nsecRdata(a, "ns.lab", &.{ 2, 46, 47 })}, &tz, 43);
    try put(w, &tz, "ns.lab", 47, &.{try nsecRdata(a, "lab", &.{ 1, 46, 47 })}, &tz, null);

    // example.lab: apex, ns, www; www's NSEC answers the DS query for www (not a cut).
    try put(w, &ez, "example.lab", 6, &.{try soaRdata(a, "example.lab")}, &ez, null);
    try put(w, &ez, "example.lab", 2, &.{try nameWire(a, "ns.example.lab")}, &ez, null);
    try put(w, &ez, "example.lab", 48, &.{ez.dnskey}, &ez, null);
    try put(w, &ez, "ns.example.lab", 1, &ns_a, &ez, null);
    const www_a: []const u8 = if (sc.alter_a) &.{ 192, 0, 2, 66 } else &.{ 192, 0, 2, 1 };
    if (sc.alter_a) w.sign_raws = &.{&.{ 192, 0, 2, 1 }};
    try put(w, &ez, "www.example.lab", 1, &.{www_a}, &ez, null);
    try put(w, &ez, "example.lab", 47, &.{try nsecRdata(a, "ns.example.lab", &.{ 2, 6, 46, 47, 48 })}, &ez, null);
    try put(w, &ez, "ns.example.lab", 47, &.{try nsecRdata(a, "www.example.lab", &.{ 1, 46, 47 })}, &ez, null);
    try put(w, &ez, "www.example.lab", 47, &.{try nsecRdata(a, "example.lab", &.{ 1, 46, 47 })}, &ez, 43);

    // The unsigned zone below the cut.
    var tmp: World = .{ .arena = a };
    var iz = try newZone(a, "insecure.lab", 5);
    try put(&tmp, &iz, "insecure.lab", 6, &.{try soaRdata(a, "insecure.lab")}, null, null);
    try put(&tmp, &iz, "insecure.lab", 2, &.{try nameWire(a, "ns.insecure.lab")}, null, null);
    try put(&tmp, &iz, "ns.insecure.lab", 1, &ns_a, null, null);
    try put(&tmp, &iz, "www.insecure.lab", 1, &.{&.{ 192, 0, 2, 9 }}, null, null);
    try w.answers.append(a, .{ .owner = "www.insecure.lab", .ty = 1, .rrset = .{ .records = try records(a, "www.insecure.lab", 1, &.{&.{ 192, 0, 2, 9 }}) } });
    insecure_text.* = iz.text;

    root_text.* = rz;
    test_text.* = tz;
    ex_text.* = ez;
}

fn verdictOfUnbound(out: []const u8) ?Verdict {
    if (std.mem.find(u8, out, "(secure)") != null) return .secure;
    if (std.mem.find(u8, out, "(insecure)") != null) return .insecure;
    if (std.mem.find(u8, out, "BOGUS") != null or std.mem.find(u8, out, "validation failure") != null) return .bogus;
    return null;
}

/// Returns the number of disagreements; prints and returns 0 when unbound-host is not installed.
pub fn run(arena: std.mem.Allocator, io: std.Io) !usize {
    const cwd = std.Io.Dir.cwd();
    for ([_][]const []const u8{ &.{ "unbound-host", "-h" }, &.{ "unshare", "--help" } }) |probe| {
        _ = std.process.run(arena, io, .{ .argv = probe }) catch {
            std.debug.print("interop-dnssec: {s} not found, walk against unbound skipped\n", .{probe[0]});
            return 0;
        };
    }
    var failures: usize = 0;
    for (scenarios) |sc| {
        var world: World = .{ .arena = arena };
        var rz = try newZone(arena, "", 1);
        var tz = try newZone(arena, "lab", 2);
        var ez = try newZone(arena, "example.lab", 3);
        var insecure: std.ArrayList(u8) = .empty;
        try build(&world, sc, &rz, &tz, &ez, &insecure);

        const dir = try arena.print("{s}/walk", .{work_dir});
        try cwd.createDirPath(io, dir);
        try cwd.writeFile(io, .{ .sub_path = try arena.print("{s}/root.zone", .{dir}), .data = rz.text.items });
        try cwd.writeFile(io, .{ .sub_path = try arena.print("{s}/test.zone", .{dir}), .data = tz.text.items });
        try cwd.writeFile(io, .{ .sub_path = try arena.print("{s}/example.zone", .{dir}), .data = ez.text.items });
        try cwd.writeFile(io, .{ .sub_path = try arena.print("{s}/insecure.zone", .{dir}), .data = insecure.items });
        var conf: std.ArrayList(u8) = .empty;
        try conf.appendSlice(arena, "server:\n  verbosity: 0\n");
        for ([_][2][]const u8{ .{ ".", "root.zone" }, .{ "lab.", "test.zone" }, .{ "example.lab.", "example.zone" }, .{ "insecure.lab.", "insecure.zone" } }) |zf| {
            try conf.print(arena, "auth-zone:\n  name: \"{s}\"\n  zonefile: \"{s}/{s}\"\n  for-upstream: yes\n  for-downstream: no\n  fallback-enabled: no\n", .{ zf[0], dir, zf[1] });
        }
        const conf_path = try arena.print("{s}/unbound.conf", .{dir});
        try cwd.writeFile(io, .{ .sub_path = conf_path, .data = conf.items });

        const anchor = try arena.print(". DNSKEY 257 3 15 {s}", .{std.base64.standard.Encoder.encode(try arena.alloc(u8, 44), &rz.kp.public_key.toBytes())});
        const res = try std.process.run(arena, io, .{ .argv = &.{ "unshare", "-rn", "unbound-host", "-C", conf_path, "-y", anchor, "-v", "-t", "A", sc.qname } });
        const theirs = verdictOfUnbound(res.stdout) orelse verdictOfUnbound(res.stderr);

        const fetcher: dnssec.walk.Fetcher = .{ .context = &world, .fetchFn = World.fetch };
        const root_dnskey = try dnssec.sign.encodeDnskey(arena, 0x0101, rdata.algorithm.ed25519, &rz.kp.public_key.toBytes());
        const mine = try dnssec.walk.validateRrset(arena, fetcher, &.{.{ .dnskey_rdata = root_dnskey }}, sc.qname, 1, .{ .now = now });
        const mine_v: Verdict = switch (mine) {
            .secure => .secure,
            .insecure => .insecure,
            else => .bogus,
        };
        const agree = theirs != null and theirs.? == mine_v and mine_v == sc.want;
        std.debug.print("interop-dnssec: walk vs unbound, {s}: walk {s}, unbound {s}, expected {s} -> {s}\n", .{ sc.name, @tagName(mine_v), if (theirs) |t| @tagName(t) else "no verdict", @tagName(sc.want), if (agree) "ok" else "DISAGREE" });
        if (!agree) {
            failures += 1;
            std.debug.print("{s}{s}\n", .{ res.stdout, res.stderr });
        }
    }
    return failures;
}
