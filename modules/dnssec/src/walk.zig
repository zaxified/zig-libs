// SPDX-License-Identifier: MIT

//! Root-to-leaf delegation chain walker (RFC 4035 §5): authenticate one RRset by climbing from a trust anchor
//! (the root zone's, or any zone's) through every zone cut to the zone that owns the RRset.
//!
//! The walker does no I/O. The caller provides a `Fetcher` (a context pointer and one function) that answers
//! "give me the RRsets of the response to `<name> <type>`", the way a stub or a recursive resolver would;
//! the walker asks for each zone's DNSKEY RRset and for the DS RRset (or its denial) of every name between the
//! anchor and the query name. The steps it takes at each name `N` below the current zone `Z`, whose DNSKEY
//! RRset is already authenticated:
//!
//!  1. DS present: the DS RRset must verify under a `Z` key (signer `Z`); the DNSKEY RRset of `N` must then
//!     be vouched for by one of those DS records (`chain.validateDnskeySetPolicy`: the matching key has to
//!     sign the whole set) with a time-valid RRSIG. `N` becomes the current zone. DS records whose algorithm
//!     or digest the policy does not support are ignored; if none is usable the chain ends `.insecure`
//!     (RFC 4035 §5.2).
//!  2. no DS: the NSEC or NSEC3 records of the response must verify under `Z`, and `nsec.proveDenial` /
//!     `nsec3.proveDenial` decide: an unsigned delegation (NS without DS or SOA, or an NSEC3 Opt-Out cover) ends
//!     the walk `.insecure`; a NODATA (the name is not a zone cut) moves on to the next label with `Z` unchanged;
//!     anything else (a proof that does not hold, no proof at all) is `.bogus`.
//!
//! Finally the RRset itself must verify under a key of the last zone (`root.validate` with the key pinned,
//! so the RRSIG window, signer name, labels and algorithm guards all apply).
//!
//! Not covered: the denial of the queried RRset itself (a NXDOMAIN / NODATA answer is proved with `nsec.proveDenial` /
//! `nsec3.proveDenial` over NSEC / NSEC3 RRsets that the caller authenticates like any other RRset: ask this function
//! for them) and the RFC 4035 §5.3.4 wildcard-expansion proof, which stays the caller's (as for `root.validate`). The
//! fetcher chooses transport, caching, retries and the data source.

const std = @import("std");
const dns = @import("dns");
const rdata = @import("rdata.zig");
const chain = @import("chain.zig");
const nsec = @import("nsec.zig");
const nsec3 = @import("nsec3.zig");
const policy_mod = @import("policy.zig");
const canonical = @import("canonical.zig");
const root = @import("root.zig");

/// One RRset of a response with its signatures: `records` share one owner name, type and class and carry their
/// RDATA as `Record.Data.unknown` for the DNSSEC types (the way `dns` decodes them); `rrsigs` are the raw RDATA of
/// the RRSIG records covering it (any number, possibly none).
pub const Rrset = struct {
    records: []const dns.Record,
    rrsigs: []const []const u8 = &.{},
};

pub const FetchError = error{
    /// The data could not be obtained (network failure, SERVFAIL, timeout). The walk stops with this error: it
    /// is neither a validation failure (`.bogus`) nor a proof of an unsigned zone.
    FetchFailed,
};

/// The seam to the caller's resolver. `fetchFn` returns every RRset of the response to the query `name` / `rr_type`
/// (answer and authority sections alike; for a DS query that is the DS RRset, or the SOA and NSEC / NSEC3 RRsets of
/// the denial). The result stays valid until the next call: the walker copies what it keeps.
pub const Fetcher = struct {
    context: *anyopaque,
    fetchFn: *const fn (context: *anyopaque, name: []const u8, rr_type: u16) FetchError![]const Rrset,

    pub fn fetch(self: Fetcher, name: []const u8, rr_type: u16) FetchError![]const Rrset {
        return self.fetchFn(self.context, name, rr_type);
    }
};

pub const WalkError = FetchError || error{OutOfMemory};

pub const Options = struct {
    /// Seconds since the epoch for every RRSIG window check (see `root.ValidateOptions.now`).
    now: u32,
    policy: policy_mod.Policy = .rfc8624,
    /// The zone the anchors belong to (default: the root).
    anchor_zone: []const u8 = "",
};

/// The IANA root zone's trust anchors as DS records: KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696),
/// algorithm 8, SHA-256 (published at https://data.iana.org/root-anchors/root-anchors.xml).
pub const root_anchors = [_]chain.TrustAnchor{
    .{ .ds = .{ .key_tag = 20326, .algorithm = 8, .digest_type = 2, .digest = &.{
        0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
        0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
    } } },
    .{ .ds = .{ .key_tag = 38696, .algorithm = 8, .digest_type = 2, .digest = &.{
        0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74, 0x12, 0x19,
        0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4, 0x44, 0xA4, 0xC0, 0xFB, 0x2B, 0x16,
    } } },
};

const max_name_len = 253;
const max_labels = 127;

/// Authenticate the RRset `qname` / `qtype` against `anchors` (all anchors of `options.anchor_zone`; one
/// verifying is enough). Returns `.secure` when the whole chain and the RRset verify, `.insecure` when an unsigned
/// delegation (or an unsupported algorithm / digest, RFC 4035 §5.2) is proved on the way, `.bogus` on any failure
/// and `.indeterminate` when no anchor is given or `qname` is not under the anchor zone (or a DS query is made
/// for the anchor zone itself). A fetcher failure returns `error.FetchFailed`. Every error on attacker-controlled
/// bytes collapses to `.bogus`.
pub fn validateRrset(
    gpa: std.mem.Allocator,
    fetcher: Fetcher,
    anchors: []const chain.TrustAnchor,
    qname: []const u8,
    qtype: u16,
    options: Options,
) WalkError!root.ValidationResult {
    if (anchors.len == 0) return .indeterminate;
    const q = canonical.stripDot(qname);
    const anchor_zone = canonical.stripDot(options.anchor_zone);
    if (q.len > max_name_len) return .bogus;
    if (!nsec.isNameOrDescendant(q, anchor_zone)) return .indeterminate;

    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // Start offset of every suffix of `q`: starts[i] .. end is the name with its last `n - i` labels.
    var starts: [max_labels + 1]u8 = undefined;
    var n: usize = 0;
    if (q.len != 0) {
        starts[0] = 0;
        n = 1;
        for (q, 0..) |c, i| {
            if (c == '.') {
                if (n > max_labels) return .bogus;
                starts[n] = @intCast(i + 1);
                n += 1;
            }
        }
    }
    const zone_labels = labelCount(anchor_zone);
    // The DS RRset of the anchor zone lives in its parent: not reachable from here.
    if (qtype == rdata.rr_type.ds and n <= zone_labels) return .indeterminate;
    // Names whose DS (or its denial) is consulted: every suffix longer than the anchor zone, the query name
    // itself included (it may be a zone apex), except that a DS RRset is owned by the parent.
    const last = if (qtype == rdata.rr_type.ds) n - 1 else n;

    var zone: []const u8 = try arena.dupe(u8, anchor_zone);
    var zone_keys: []const []const u8 = switch (try establishKeys(gpa, arena, fetcher, zone, anchors, options)) {
        .keys => |k| k,
        .verdict => |v| return v,
    };

    var k = zone_labels + 1;
    while (k <= last) : (k += 1) {
        const name = q[starts[n - k]..];
        const resp = try fetcher.fetch(name, rdata.rr_type.ds);
        if (findRrset(resp, name, rdata.rr_type.ds)) |ds_set| {
            if (!try verifiedBy(gpa, ds_set, zone, zone_keys, options)) return .bogus;
            var candidates: std.ArrayList(chain.TrustAnchor) = .empty;
            for (ds_set.records) |r| {
                const raw = rawOf(r) orelse continue;
                const parsed = rdata.parseDs(raw) catch continue;
                try candidates.append(arena, .{ .ds = .{
                    .key_tag = parsed.key_tag,
                    .algorithm = parsed.algorithm,
                    .digest_type = parsed.digest_type,
                    .digest = try arena.dupe(u8, parsed.digest),
                } });
            }
            if (candidates.items.len == 0) return .bogus;
            const next_zone = try arena.dupe(u8, name);
            zone_keys = switch (try establishKeys(gpa, arena, fetcher, next_zone, candidates.items, options)) {
                .keys => |keys_| keys_,
                .verdict => |v| return v,
            };
            zone = next_zone;
        } else {
            switch (try proveNoDs(gpa, arena, resp, name, zone, zone_keys, options)) {
                .insecure => return .insecure,
                .no_data => {},
                else => return .bogus,
            }
        }
    }

    const resp = try fetcher.fetch(q, qtype);
    const set = findRrset(resp, q, qtype) orelse return .bogus;
    return if (try verifiedBy(gpa, set, zone, zone_keys, options)) .secure else .bogus;
}

const Established = union(enum) {
    keys: []const []const u8,
    verdict: root.ValidationResult,
};

/// Fetch the DNSKEY RRset of `zone` and authenticate it against one of `anchors`.
fn establishKeys(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    fetcher: Fetcher,
    zone: []const u8,
    anchors: []const chain.TrustAnchor,
    options: Options,
) WalkError!Established {
    const resp = try fetcher.fetch(zone, rdata.rr_type.dnskey);
    const set = findRrset(resp, zone, rdata.rr_type.dnskey) orelse return .{ .verdict = .bogus };
    const raws = try arena.alloc([]const u8, set.records.len);
    for (set.records, raws) |r, *out| out.* = rawOf(r) orelse return .{ .verdict = .bogus };

    var usable = false;
    for (anchors) |a| {
        if (chain.anchorUnsupported(options.policy, a)) continue;
        usable = true;
        for (set.rrsigs) |raw_sig| {
            const sig = rdata.parseRrsig(gpa, raw_sig) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue,
            };
            defer gpa.free(sig.signer_name);
            if (!root.rrsigTimeValid(sig, options.now)) continue;
            const res = try chain.validateDnskeySetPolicy(gpa, zone, raws, sig, a, options.policy);
            if (res != .secure) continue;
            const kept = try arena.alloc([]const u8, raws.len);
            for (raws, kept) |src, *dst| dst.* = try arena.dupe(u8, src);
            return .{ .keys = kept };
        }
    }
    // No usable anchor at all (every DS names an unsupported algorithm or digest): RFC 4035 §5.2, insecure.
    return .{ .verdict = if (usable) .bogus else .insecure };
}

/// The denial of a DS RRset at `name` (the response `resp` to the DS query): the NSEC / NSEC3 RRsets that verify under
/// the keys of `zone` are handed to the matching `proveDenial`.
fn proveNoDs(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    resp: []const Rrset,
    name: []const u8,
    zone: []const u8,
    zone_keys: []const []const u8,
    options: Options,
) WalkError!nsec.DenialResult {
    var nsec_records: std.ArrayList(nsec.NsecRecord) = .empty;
    var nsec3_records: std.ArrayList(nsec3.Nsec3Record) = .empty;
    for (resp) |set| {
        if (set.records.len == 0) continue;
        const ty: u16 = @backingInt(set.records[0].ty);
        if (ty != rdata.rr_type.nsec and ty != rdata.rr_type.nsec3) continue;
        if (!try verifiedBy(gpa, set, zone, zone_keys, options)) continue;
        for (set.records) |r| {
            const raw = rawOf(r) orelse continue;
            if (ty == rdata.rr_type.nsec) {
                const parsed = rdata.parseNsec(arena, raw) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => continue,
                };
                try nsec_records.append(arena, .{ .owner = r.name, .rdata = parsed });
            } else {
                const parsed = rdata.parseNsec3(raw) catch continue;
                const owner = canonical.stripDot(r.name);
                const dot = std.mem.findScalar(u8, owner, '.') orelse owner.len;
                try nsec3_records.append(arena, .{ .owner_hash_label = owner[0..dot], .rdata = parsed });
            }
        }
    }
    if (nsec_records.items.len != 0) return nsec.proveDenial(name, rdata.rr_type.ds, .{ .records = nsec_records.items });
    if (nsec3_records.items.len != 0) {
        const p = nsec3_records.items[0].rdata;
        const verdict = nsec3.proveDenial(name, rdata.rr_type.ds, .{ .records = nsec3_records.items }, p.salt, p.iterations);
        return switch (verdict) {
            .name_error => .name_error,
            .no_data => .no_data,
            .wildcard_answer => .wildcard_answer,
            .insecure => .insecure,
            .bogus => .bogus,
        };
    }
    return .bogus;
}

/// Whether some RRSIG of `set` verifies it under one of `keys` (raw DNSKEY RDATA of `zone`, already authenticated):
/// signer `zone`, covered type, key tag and algorithm of that key, and everything `root.validate` checks.
fn verifiedBy(
    gpa: std.mem.Allocator,
    set: Rrset,
    zone: []const u8,
    keys_: []const []const u8,
    options: Options,
) WalkError!bool {
    if (set.records.len == 0) return false;
    const first = set.records[0];
    for (set.rrsigs) |raw_sig| {
        const sig = rdata.parseRrsig(gpa, raw_sig) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
        defer gpa.free(sig.signer_name);
        if (sig.type_covered != @backingInt(first.ty)) continue;
        if (!nsec.namesEqual(sig.signer_name, zone)) continue;
        for (keys_) |raw_key| {
            const dk = rdata.parseDnskey(raw_key) catch continue;
            if (dk.algorithm != sig.algorithm) continue;
            if (rdata.keyTag(raw_key, dk.algorithm) != sig.key_tag) continue;
            const res = try root.validate(gpa, set.records, sig, first.name, dk, .{ .dnskey_rdata = raw_key }, .{
                .now = options.now,
                .policy = options.policy,
            });
            if (res == .secure) return true;
        }
    }
    return false;
}

fn findRrset(resp: []const Rrset, name: []const u8, ty: u16) ?Rrset {
    for (resp) |set| {
        if (set.records.len == 0) continue;
        const first = set.records[0];
        if (@backingInt(first.ty) != ty) continue;
        if (!nsec.namesEqual(first.name, name)) continue;
        return set;
    }
    return null;
}

fn rawOf(r: dns.Record) ?[]const u8 {
    return switch (r.data) {
        .unknown => |raw| raw,
        else => null,
    };
}

fn labelCount(name: []const u8) usize {
    if (name.len == 0) return 0;
    return std.mem.count(u8, name, ".") + 1;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const sign = @import("sign.zig");
const wire = @import("wire.zig");
const base32 = @import("base32");
const Ed25519 = std.crypto.sign.Ed25519;

const now: u32 = 1_500_000;
const inception: u32 = 1_000_000;
const expiration: u32 = 2_000_000;

const TestZone = struct {
    name: []const u8,
    kp: Ed25519.KeyPair,
    dnskey: []const u8,
    tag: u16,

    fn init(a: std.mem.Allocator, name: []const u8, seed_byte: u8) !TestZone {
        const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed_byte)));
        const dk = try sign.encodeDnskey(a, 0x0101, rdata.algorithm.ed25519, &kp.public_key.toBytes());
        return .{ .name = name, .kp = kp, .dnskey = dk, .tag = rdata.keyTag(dk, rdata.algorithm.ed25519) };
    }
};

const Resp = struct { name: []const u8, ty: u16, sets: []const Rrset };

const World = struct {
    a: std.mem.Allocator,
    resps: std.ArrayList(Resp) = .empty,
    fetches: usize = 0,

    fn put(w: *World, name: []const u8, ty: u16, sets: []const Rrset) !void {
        for (w.resps.items) |*r| {
            if (r.ty == ty and std.mem.eql(u8, r.name, name)) {
                r.sets = sets;
                return;
            }
        }
        try w.resps.append(w.a, .{ .name = name, .ty = ty, .sets = sets });
    }

    fn fetcher(w: *World) Fetcher {
        return .{ .context = w, .fetchFn = fetchImpl };
    }

    fn fetchImpl(ctx: *anyopaque, name: []const u8, ty: u16) FetchError![]const Rrset {
        const w: *World = @ptrCast(@alignCast(ctx));
        w.fetches += 1;
        for (w.resps.items) |r| {
            if (r.ty == ty and std.ascii.eqlIgnoreCase(r.name, name)) return r.sets;
        }
        return &.{};
    }
};

fn unknownRecord(name: []const u8, ty: u16, raw: []const u8) dns.Record {
    return .{ .name = name, .ty = @fromBackingInt(@intCast(ty)), .class = .in, .ttl = 3600, .data = .{ .unknown = raw } };
}

/// One signed RRset of unknown-data records.
fn signedSet(a: std.mem.Allocator, owner: []const u8, ty: u16, raws: []const []const u8, signer: TestZone) !Rrset {
    const recs = try a.alloc(dns.Record, raws.len);
    for (raws, recs) |raw, *r| r.* = unknownRecord(owner, ty, raw);
    return signRecords(a, recs, owner, signer);
}

fn signRecords(a: std.mem.Allocator, recs: []const dns.Record, owner: []const u8, signer: TestZone) !Rrset {
    const sig = try sign.signRrset(a, recs, owner, .{ .ed25519 = &signer.kp }, .{
        .signer_name = signer.name,
        .key_tag = signer.tag,
        .inception = inception,
        .expiration = expiration,
    });
    const sigs = try a.alloc([]const u8, 1);
    sigs[0] = sig;
    return .{ .records = recs, .rrsigs = sigs };
}

fn oneSet(a: std.mem.Allocator, s: Rrset) ![]const Rrset {
    const out = try a.alloc(Rrset, 1);
    out[0] = s;
    return out;
}

fn bitmap(a: std.mem.Allocator, types: []const u16) ![]u8 {
    var bits: [32]u8 = @splat(0);
    var top: usize = 0;
    for (types) |t| {
        std.debug.assert(t < 256);
        bits[t / 8] |= @as(u8, 0x80) >> @intCast(t % 8);
        top = @max(top, t / 8 + 1);
    }
    const out = try a.alloc(u8, 2 + top);
    out[0] = 0;
    out[1] = @intCast(top);
    @memcpy(out[2..], bits[0..top]);
    return out;
}

fn nsecRdata(a: std.mem.Allocator, next: []const u8, types: []const u16) ![]u8 {
    var nb: [wire.max_canonical_wire_len]u8 = undefined;
    const next_wire = try wire.encodeCanonicalName(next, &nb);
    const bm = try bitmap(a, types);
    return std.mem.concat(a, u8, &.{ next_wire, bm });
}

fn dsRdata(a: std.mem.Allocator, child: TestZone) ![]u8 {
    return sign.encodeDs(a, child.name, child.dnskey, rdata.Ds.digest_sha256);
}

const Chain = struct {
    w: World,
    root_zone: TestZone,
    org: TestZone,
    example: TestZone,
    anchor: chain.TrustAnchor,

    /// root -> org -> example.org, all Ed25519; `www.example.org A`, an unsigned delegation `insecure.org`.
    fn init(a: std.mem.Allocator) !*Chain {
        const c = try a.create(Chain);
        c.* = .{
            .w = .{ .a = a },
            .root_zone = try TestZone.init(a, "", 1),
            .org = try TestZone.init(a, "org", 2),
            .example = try TestZone.init(a, "example.org", 3),
            .anchor = undefined,
        };
        const w = &c.w;
        const root_ds = try dsRdata(a, c.root_zone);
        c.anchor = .{ .ds = try rdata.parseDs(root_ds) };

        try w.put("", rdata.rr_type.dnskey, try oneSet(a, try signedSet(a, "", rdata.rr_type.dnskey, &.{c.root_zone.dnskey}, c.root_zone)));
        try w.put("org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "org", rdata.rr_type.ds, &.{try dsRdata(a, c.org)}, c.root_zone)));
        try w.put("org", rdata.rr_type.dnskey, try oneSet(a, try signedSet(a, "org", rdata.rr_type.dnskey, &.{c.org.dnskey}, c.org)));
        try w.put("example.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "example.org", rdata.rr_type.ds, &.{try dsRdata(a, c.example)}, c.org)));
        try w.put("example.org", rdata.rr_type.dnskey, try oneSet(a, try signedSet(a, "example.org", rdata.rr_type.dnskey, &.{c.example.dnskey}, c.example)));

        const www = [_]dns.Record{.{ .name = "www.example.org", .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, 1 } } }};
        try w.put("www.example.org", 1, try oneSet(a, try signRecords(a, try a.dupe(dns.Record, &www), "www.example.org", c.example)));
        // www.example.org is no zone cut: its NSEC proves NODATA for DS.
        const www_nsec = try nsecRdata(a, "zzz.example.org", &.{ 1, rdata.rr_type.rrsig, rdata.rr_type.nsec });
        try w.put("www.example.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "www.example.org", rdata.rr_type.nsec, &.{www_nsec}, c.example)));

        // insecure.org: a delegation without DS (NS, no SOA, no DS in the NSEC bitmap).
        const ins_nsec = try nsecRdata(a, "j.org", &.{ 2, rdata.rr_type.rrsig, rdata.rr_type.nsec });
        try w.put("insecure.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "insecure.org", rdata.rr_type.nsec, &.{ins_nsec}, c.org)));
        const sub = [_]dns.Record{.{ .name = "www.insecure.org", .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 192, 0, 2, 9 } } }};
        try w.put("www.insecure.org", 1, &.{.{ .records = try a.dupe(dns.Record, &sub) }});
        return c;
    }

    fn run(c: *Chain, name: []const u8, ty: u16) !root.ValidationResult {
        return validateRrset(testing.allocator, c.w.fetcher(), &.{c.anchor}, name, ty, .{ .now = now });
    }
};

test "walk: root to leaf, three zones, secure; fetches stay bounded" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const c = try Chain.init(arena.allocator());
    try testing.expectEqual(root.ValidationResult.secure, try c.run("www.example.org", 1));
    // root DNSKEY + (DS, DNSKEY) x 2 + DS(www) + the RRset.
    try testing.expectEqual(@as(usize, 1 + 4 + 1 + 1), c.w.fetches);
    // A trailing dot and another case do not matter.
    try testing.expectEqual(root.ValidationResult.secure, try c.run("WWW.Example.ORG.", 1));
}

test "walk: DNSKEY and DS RRsets as the query" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const c = try Chain.init(arena.allocator());
    try testing.expectEqual(root.ValidationResult.secure, try c.run("example.org", rdata.rr_type.dnskey));
    try testing.expectEqual(root.ValidationResult.secure, try c.run("example.org", rdata.rr_type.ds));
    try testing.expectEqual(root.ValidationResult.secure, try c.run("org", rdata.rr_type.ds));
    try testing.expectEqual(root.ValidationResult.indeterminate, try c.run("", rdata.rr_type.ds));
}

test "walk: an unsigned delegation proved by NSEC is insecure" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const c = try Chain.init(arena.allocator());
    try testing.expectEqual(root.ValidationResult.insecure, try c.run("www.insecure.org", 1));
}

test "walk: a tampered answer, DS digest, DNSKEY or signature is bogus" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    {
        const c = try Chain.init(a);
        const evil = [_]dns.Record{.{ .name = "www.example.org", .ty = .a, .class = .in, .ttl = 300, .data = .{ .a = .{ 6, 6, 6, 6 } } }};
        var set = (try c.w.fetcher().fetch("www.example.org", 1))[0];
        set.records = try a.dupe(dns.Record, &evil);
        try c.w.put("www.example.org", 1, try oneSet(a, set));
        try testing.expectEqual(root.ValidationResult.bogus, try c.run("www.example.org", 1));
    }
    {
        // A DS of the wrong key (the org zone's own DS names example.org's parent key: swap in a stranger).
        const c = try Chain.init(a);
        const stranger = try TestZone.init(a, "example.org", 77);
        try c.w.put("example.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "example.org", rdata.rr_type.ds, &.{try dsRdata(a, stranger)}, c.org)));
        try testing.expectEqual(root.ValidationResult.bogus, try c.run("www.example.org", 1));
    }
    {
        // The DNSKEY RRset signed by a key the DS does not vouch for.
        const c = try Chain.init(a);
        const stranger = try TestZone.init(a, "example.org", 78);
        try c.w.put("example.org", rdata.rr_type.dnskey, try oneSet(a, try signedSet(a, "example.org", rdata.rr_type.dnskey, &.{ c.example.dnskey, stranger.dnskey }, stranger)));
        try testing.expectEqual(root.ValidationResult.bogus, try c.run("www.example.org", 1));
    }
    {
        // A DS RRset not signed by the parent's key.
        const c = try Chain.init(a);
        const stranger = try TestZone.init(a, "org", 79);
        try c.w.put("example.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "example.org", rdata.rr_type.ds, &.{try dsRdata(a, c.example)}, stranger)));
        try testing.expectEqual(root.ValidationResult.bogus, try c.run("www.example.org", 1));
    }
    {
        // Neither a DS nor its denial: a downgrade attempt.
        const c = try Chain.init(a);
        try c.w.put("example.org", rdata.rr_type.ds, &.{});
        try testing.expectEqual(root.ValidationResult.bogus, try c.run("www.example.org", 1));
    }
    {
        // The wrong trust anchor.
        const c = try Chain.init(a);
        const other = try TestZone.init(a, "", 90);
        const anchor: chain.TrustAnchor = .{ .ds = try rdata.parseDs(try dsRdata(a, other)) };
        try testing.expectEqual(root.ValidationResult.bogus, try validateRrset(testing.allocator, c.w.fetcher(), &.{anchor}, "www.example.org", 1, .{ .now = now }));
    }
}

test "walk: expired and not-yet-valid signatures are bogus at every level" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const c = try Chain.init(arena.allocator());
    for ([_]u32{ inception - 1, expiration + 1 }) |t| {
        const r = try validateRrset(testing.allocator, c.w.fetcher(), &.{c.anchor}, "www.example.org", 1, .{ .now = t });
        try testing.expectEqual(root.ValidationResult.bogus, r);
    }
}

test "walk: an NSEC that does not prove the absence of DS is bogus" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try Chain.init(a);
    // The NSEC bitmap claims a DS exists although none was delivered.
    const lying = try nsecRdata(a, "j.org", &.{ 2, rdata.rr_type.ds, rdata.rr_type.rrsig, rdata.rr_type.nsec });
    try c.w.put("insecure.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "insecure.org", rdata.rr_type.nsec, &.{lying}, c.org)));
    try testing.expectEqual(root.ValidationResult.bogus, try c.run("www.insecure.org", 1));
    // A valid NSEC whose signature is forged (signed by the wrong zone) does not count at all.
    const stranger = try TestZone.init(a, "org", 91);
    const ins_nsec = try nsecRdata(a, "j.org", &.{ 2, rdata.rr_type.rrsig, rdata.rr_type.nsec });
    try c.w.put("insecure.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "insecure.org", rdata.rr_type.nsec, &.{ins_nsec}, stranger)));
    try testing.expectEqual(root.ValidationResult.bogus, try c.run("www.insecure.org", 1));
}

test "walk: an NSEC3 Opt-Out cover is insecure, and a DS with an unsupported algorithm too" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c = try Chain.init(a);

    // NSEC3 chain of the org zone: org itself matches (closest encloser), a single opt-out span covers the rest.
    const salt = "\xaa";
    const iters: u16 = 2;
    var nb: [wire.max_canonical_wire_len]u8 = undefined;
    const org_hash = nsec3.iteratedHash(try wire.encodeCanonicalName("org", &nb), salt, iters);
    var label_buf: [32]u8 = undefined;
    const org_label = try base32.encode(&label_buf, &org_hash, .{ .alphabet = .hex, .pad = false });
    const owner = try std.fmt.allocPrint(a, "{s}.org", .{org_label});
    // next hash = own hash: one record whose span wraps around the whole circle (covers everything but itself).
    const bm = try bitmap(a, &.{ 2, 6, rdata.rr_type.dnskey, rdata.rr_type.rrsig, rdata.rr_type.nsec3param });
    const n3 = try std.mem.concat(a, u8, &.{ &[_]u8{ 1, 1, 0, iters, salt.len }, salt, &[_]u8{org_hash.len}, &org_hash, bm });
    try c.w.put("insecure.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, owner, rdata.rr_type.nsec3, &.{n3}, c.org)));
    try testing.expectEqual(root.ValidationResult.insecure, try c.run("www.insecure.org", 1));

    // The same record without the opt-out flag proves NXDOMAIN of the DS name: not a delegation proof.
    const n3_strict = try a.dupe(u8, n3);
    n3_strict[1] = 0;
    try c.w.put("insecure.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, owner, rdata.rr_type.nsec3, &.{n3_strict}, c.org)));
    try testing.expectEqual(root.ValidationResult.bogus, try c.run("www.insecure.org", 1));

    // A DS naming only an unsupported algorithm (RSAMD5): the zone is insecure (RFC 4035 §5.2).
    const md5_ds = [_]u8{ 0, 1, 1, 2, 0xde, 0xad };
    try c.w.put("example.org", rdata.rr_type.ds, try oneSet(a, try signedSet(a, "example.org", rdata.rr_type.ds, &.{&md5_ds}, c.org)));
    try testing.expectEqual(root.ValidationResult.insecure, try c.run("www.example.org", 1));
}

test "walk: a fetch failure is an error, a missing anchor is indeterminate, a foreign name too" {
    const Failing = struct {
        fn f(_: *anyopaque, _: []const u8, _: u16) FetchError![]const Rrset {
            return error.FetchFailed;
        }
    };
    var dummy: u8 = 0;
    const fetcher: Fetcher = .{ .context = &dummy, .fetchFn = Failing.f };
    try testing.expectError(error.FetchFailed, validateRrset(testing.allocator, fetcher, &root_anchors, "example.org", 1, .{ .now = now }));
    try testing.expectEqual(root.ValidationResult.indeterminate, try validateRrset(testing.allocator, fetcher, &.{}, "example.org", 1, .{ .now = now }));
    try testing.expectEqual(root.ValidationResult.indeterminate, try validateRrset(testing.allocator, fetcher, &root_anchors, "example.org", 1, .{ .now = now, .anchor_zone = "com" }));
}

test "walk: an anchor below the root starts the chain there" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const c = try Chain.init(arena.allocator());
    const org_anchor: chain.TrustAnchor = .{ .dnskey_rdata = c.org.dnskey };
    const r = try validateRrset(testing.allocator, c.w.fetcher(), &.{org_anchor}, "www.example.org", 1, .{ .now = now, .anchor_zone = "org" });
    try testing.expectEqual(root.ValidationResult.secure, r);
}

test "root_anchors match the IANA root KSK DNSKEY records" {
    // data.iana.org root-anchors / dns-root-data root.key (public data), keys for the tags 20326 and 38696.
    const keys_b64 = [_][]const u8{
        "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
        KSK2024_B64,
    };
    for (keys_b64, root_anchors) |b64, anchor| {
        var raw: [4 + 300]u8 = undefined;
        const len = try std.base64.standard.Decoder.calcSizeForSlice(b64);
        raw[0..4].* = .{ 0x01, 0x01, 3, 8 };
        try std.base64.standard.Decoder.decode(raw[4..][0..len], b64);
        const dnskey = raw[0 .. 4 + len];
        try testing.expectEqual(anchor.ds.key_tag, rdata.keyTag(dnskey, 8));
        try testing.expect(try ds_mod.matches(anchor.ds, "", dnskey));
        try testing.expect(chain.anchorMatches(anchor, "", dnskey));
    }
}

const ds_mod = @import("ds.zig");
const KSK2024_B64 = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";
