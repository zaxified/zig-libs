// SPDX-License-Identifier: MIT

//! RFC 4034 §3.1.8.1 canonical signed-data construction — THE piece an RRSIG
//! signature is actually computed over.
//!
//! For an RRset `{RR_1, ..., RR_n}` covered by `rrsig`, the signed data is:
//!
//!   RRSIG_RDATA (the RRSIG's own RDATA, MINUS the final Signature field)
//!   || RR_1' || RR_2' || ... || RR_n'    (each RR in CANONICAL FORM,
//!                                          in CANONICAL ORDER)
//!
//! where each RR' is:
//!
//!   owner_name (§6.1 canonical form: every US-ASCII letter lowercased,
//!               uncompressed; if `rrsig.labels` < the owner name's actual
//!               label count, this is a WILDCARD expansion — the signed name
//!               is "*.<the rightmost `rrsig.labels` labels>", NOT the
//!               expanded query name, per §3.1.3 / §5.3.2)
//!   || TYPE || CLASS || rrsig.original_ttl   (§6.2 — the ORIGINAL TTL from
//!               the RRSIG, NOT the RR's own on-the-wire TTL, which may have
//!               decayed in a cache)
//!   || RDLENGTH || RDATA (§6.2: any DOMAIN NAME embedded inside the RDATA of
//!               the RFC-4034-§6.2 name-bearing types — NS/CNAME/PTR/MX/SOA/
//!               SRV here — is lowercased and de-compressed; everything else
//!               in RDATA is copied verbatim)
//!
//! and canonical ORDER (§6.3) sorts the RRs by comparing their
//! post-canonicalization RDATA as left-justified unsigned octet sequences
//! (a strict prefix sorts first — `std.mem.lessThan`), NOT by owner name
//! (the whole RRset shares one) and NOT numerically.
//!
//! Verified byte-exact: the output of this function is fed straight into
//! `keys.verifySignature` against real RRSIGs produced by `ldns-signzone`
//! across algorithms 8/13/14/15 (RSA/ECDSA-P256/ECDSA-P384/Ed25519), for
//! SOA/NS/MX/TXT/A/NSEC/DNSKEY RRsets and a wildcard-expanded A — a real
//! signature cannot verify unless every byte here is correct. Source zones
//! independently cross-checked with `ldns-verify-zone`. See
//! `oracle_vectors.zig` + the `oracle_test.zig` KATs.

const std = @import("std");
const dns = @import("dns");
const rdata = @import("rdata.zig");
const wire = @import("wire.zig");

pub const BuildSignedDataError = error{
    OutOfMemory,
    /// The RRset is empty, or its records don't share one owner
    /// name/type/class (a malformed input this function should refuse
    /// rather than silently sign garbage).
    InconsistentRrset,
    /// An OPT pseudo-record (RFC 6891) was handed in as if it were signable —
    /// it never is (it carries no zone data and is never covered by an RRSIG).
    NotSignable,
} || wire.NameError;

/// Build the RFC 4034 §3.1.8.1 canonical signed-data byte stream for
/// `rrset` (all sharing one owner name/type/class) under `rrsig`. Returns an
/// allocator-owned buffer the caller frees.
pub fn buildSignedData(gpa: std.mem.Allocator, rrset: []const dns.Record, rrsig: rdata.Rrsig, owner_name: []const u8) BuildSignedDataError![]u8 {
    if (rrset.len == 0) return error.InconsistentRrset;
    const ty = rrset[0].ty;
    const class = rrset[0].class;
    for (rrset) |r| {
        if (r.ty != ty or r.class != class) return error.InconsistentRrset;
        if (!std.ascii.eqlIgnoreCase(stripDot(r.name), stripDot(owner_name))) return error.InconsistentRrset;
        // Audit F7: `dns` decodes a name to dotted TEXT without escaping a
        // literal `.` inside one label, so three DIFFERENT wire owner names
        // (3 labels / 1 label / 2 labels, all containing dots) can decode to
        // the SAME text "a.b.c" -- the text check above alone would accept
        // any of them as this RRset's owner. `r.labels` (populated by
        // `dns.decode`, empty for a hand-built `Record` whose structure is
        // simply unknown here -- e.g. `chain.zig`'s synthetic DNSKEY
        // records, or a test fixture) is the wire ground truth: when
        // present, it must count the same as the text's OWN dot-count, or
        // this record's text is not a faithful rendering of its wire name
        // and this function refuses to sign over an ambiguity it cannot
        // resolve. A `Record` with `labels.len == 0` skips this (nothing to
        // cross-check), same as before this fix -- no behavior change for
        // any caller that does not populate it.
        if (r.labels.len != 0 and labelCount(stripDot(r.name)) != r.labels.len) return error.InconsistentRrset;
    }

    // Scratch arena for the per-RR canonical buffers we sort before emitting.
    var arena_inst = std.heap.ArenaAllocator.init(gpa);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // The owner name every RR is signed under (wildcard-aware, §3.1.3).
    var owner_wire_buf: [wire.max_canonical_wire_len]u8 = undefined;
    const owner_wire = try signedOwnerName(owner_name, rrsig.labels, &owner_wire_buf);

    const Item = struct { rr: []u8, rdata: []u8 };
    var items = try arena.alloc(Item, rrset.len);
    for (rrset, 0..) |r, i| {
        const canon_rdata = try canonicalRdata(arena, r);
        if (canon_rdata.len > std.math.maxInt(u16)) return error.InconsistentRrset;
        // owner || TYPE(2) || CLASS(2) || original_ttl(4) || RDLENGTH(2) || RDATA
        var rr: std.ArrayList(u8) = .empty;
        try rr.appendSlice(arena, owner_wire);
        try appendInt(&rr, arena, u16, rrsig.type_covered);
        try appendInt(&rr, arena, u16, @intFromEnum(class));
        try appendInt(&rr, arena, u32, rrsig.original_ttl);
        try appendInt(&rr, arena, u16, @intCast(canon_rdata.len));
        const rdata_off = rr.items.len;
        try rr.appendSlice(arena, canon_rdata);
        items[i] = .{ .rr = rr.items, .rdata = rr.items[rdata_off..] };
    }

    // Canonical RR order (§6.3): sort by RDATA as unsigned octet strings.
    std.mem.sort(Item, items, {}, struct {
        fn lessThan(_: void, a: Item, b: Item) bool {
            return std.mem.lessThan(u8, a.rdata, b.rdata);
        }
    }.lessThan);

    // RRSIG_RDATA (through the signer's name; signature excluded) || sorted RRs.
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try appendInt(&out, gpa, u16, rrsig.type_covered);
    try out.append(gpa, rrsig.algorithm);
    try out.append(gpa, rrsig.labels);
    try appendInt(&out, gpa, u32, rrsig.original_ttl);
    try appendInt(&out, gpa, u32, rrsig.expiration);
    try appendInt(&out, gpa, u32, rrsig.inception);
    try appendInt(&out, gpa, u16, rrsig.key_tag);
    var signer_buf: [wire.max_canonical_wire_len]u8 = undefined;
    try out.appendSlice(gpa, try wire.encodeCanonicalName(rrsig.signer_name, &signer_buf));
    for (items) |it| try out.appendSlice(gpa, it.rr);

    return try out.toOwnedSlice(gpa);
}

fn stripDot(name: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, name, ".")) name[0 .. name.len - 1] else name;
}

fn appendInt(list: *std.ArrayList(u8), gpa: std.mem.Allocator, comptime T: type, value: T) error{OutOfMemory}!void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .big);
    try list.appendSlice(gpa, &buf);
}

/// The owner name each RR is signed under (RFC 4034 §3.1.3 / RFC 4035
/// §5.3.2): the owner in canonical wire form, unless the RRset was
/// wildcard-synthesized (`labels` < the owner's own label count), in which
/// case it is `*.` prepended to the rightmost `labels` labels of the owner.
fn signedOwnerName(owner_name: []const u8, labels: u8, out: *[wire.max_canonical_wire_len]u8) wire.NameError![]u8 {
    const owner = stripDot(owner_name);
    const n = labelCount(owner);
    if (labels >= n) return wire.encodeCanonicalName(owner, out);
    const suffix = lastLabels(owner, labels);
    // Build "*." ++ suffix (or just "*" at the root) then canonically encode.
    var text_buf: [2 + wire.max_name_text_len]u8 = undefined;
    var w: std.Io.Writer = .fixed(&text_buf);
    w.writeByte('*') catch return error.NameTooLong;
    if (suffix.len != 0) {
        w.writeByte('.') catch return error.NameTooLong;
        w.writeAll(suffix) catch return error.NameTooLong;
    }
    return wire.encodeCanonicalName(w.buffered(), out);
}

fn labelCount(name: []const u8) u8 {
    if (name.len == 0) return 0;
    var count: u8 = 1;
    for (name) |c| {
        if (c == '.') count += 1;
    }
    return count;
}

/// The rightmost `want` labels of `name` (a slice into `name`).
fn lastLabels(name: []const u8, want: u8) []const u8 {
    if (want == 0) return name[name.len..];
    const total = labelCount(name);
    if (want >= total) return name;
    var to_drop: usize = total - want;
    var i: usize = 0;
    while (to_drop != 0) : (i += 1) {
        if (name[i] == '.') to_drop -= 1;
    }
    return name[i..];
}

/// The canonical RDATA (RFC 4034 §6.2) for one record, allocated in `gpa`:
/// embedded domain names in the §6.2 name-bearing types are lowercased and
/// uncompressed; every other byte is copied verbatim. Types that arrive as
/// raw `.unknown` RDATA (DNSKEY/RRSIG/DS/NSEC/NSEC3/…) are already in
/// canonical wire form as decoded and pass through untouched — RFC 6840 §5.1
/// specifies NSEC's Next Domain Name and post-RFC-4034 types are NOT
/// downcased, which raw passthrough gives for free.
fn canonicalRdata(gpa: std.mem.Allocator, r: dns.Record) BuildSignedDataError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    switch (r.data) {
        .a => |v| try out.appendSlice(gpa, &v),
        .aaaa => |v| try out.appendSlice(gpa, &v),
        .cname, .ns, .ptr => |name| try appendCanonicalName(&out, gpa, name),
        .mx => |mx| {
            try appendInt(&out, gpa, u16, mx.preference);
            try appendCanonicalName(&out, gpa, mx.exchange);
        },
        .txt => |strings| for (strings) |s| {
            if (s.len > std.math.maxInt(u8)) return error.InconsistentRrset;
            try out.append(gpa, @intCast(s.len));
            try out.appendSlice(gpa, s);
        },
        .soa => |soa| {
            try appendCanonicalName(&out, gpa, soa.mname);
            try appendCanonicalName(&out, gpa, soa.rname);
            try appendInt(&out, gpa, u32, soa.serial);
            try appendInt(&out, gpa, u32, soa.refresh);
            try appendInt(&out, gpa, u32, soa.retry);
            try appendInt(&out, gpa, u32, soa.expire);
            try appendInt(&out, gpa, u32, soa.minimum);
        },
        .srv => |srv| {
            try appendInt(&out, gpa, u16, srv.priority);
            try appendInt(&out, gpa, u16, srv.weight);
            try appendInt(&out, gpa, u16, srv.port);
            try appendCanonicalName(&out, gpa, srv.target);
        },
        .caa => |caa| {
            try out.append(gpa, caa.flags);
            if (caa.tag.len > std.math.maxInt(u8)) return error.InconsistentRrset;
            try out.append(gpa, @intCast(caa.tag.len));
            try out.appendSlice(gpa, caa.tag);
            try out.appendSlice(gpa, caa.value);
        },
        .opt => return error.NotSignable,
        .unknown => |raw| try out.appendSlice(gpa, raw),
    }
    return try out.toOwnedSlice(gpa);
}

fn appendCanonicalName(list: *std.ArrayList(u8), gpa: std.mem.Allocator, name: []const u8) BuildSignedDataError!void {
    var buf: [wire.max_canonical_wire_len]u8 = undefined;
    try list.appendSlice(gpa, try wire.encodeCanonicalName(name, &buf));
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn testARecord(name: []const u8, labels: []const []const u8) dns.Record {
    return .{
        .name = name,
        .ty = .a,
        .class = .in,
        .ttl = 60,
        .data = .{ .a = .{ 1, 2, 3, 4 } },
        .labels = labels,
    };
}

const zero_rrsig: rdata.Rrsig = .{
    .type_covered = 1, // A
    .algorithm = 0,
    .labels = 3,
    .original_ttl = 60,
    .expiration = 0,
    .inception = 0,
    .key_tag = 0,
    .signer_name = "a.b.c",
    .signature = "",
};

test "buildSignedData: F7 -- one collapsed text, three different wire label structures, each refused against its own owner text" {
    // The audit's exact collision: "\x01a\x01b\x01c\x00" (3 labels),
    // "\x05a.b.c\x00" (1 label), "\x03a.b\x01c\x00" (2 labels) all decode to
    // the dotted text "a.b.c" -- but only the FIRST is a faithful rendering
    // of it (labelCount("a.b.c") == 3). The other two must be refused on
    // their own, standalone, one-record "RRset": the ambiguity is in the
    // record itself, not only in mixing it with a sibling.
    const one_label = [_][]const u8{"a.b.c"};
    const two_labels = [_][]const u8{ "a.b", "c" };
    const three_labels = [_][]const u8{ "a", "b", "c" };

    const rr_1 = [_]dns.Record{testARecord("a.b.c", &one_label)};
    try testing.expectError(error.InconsistentRrset, buildSignedData(testing.allocator, &rr_1, zero_rrsig, "a.b.c"));

    const rr_2 = [_]dns.Record{testARecord("a.b.c", &two_labels)};
    try testing.expectError(error.InconsistentRrset, buildSignedData(testing.allocator, &rr_2, zero_rrsig, "a.b.c"));

    // The TRUE 3-label rendering is accepted on its own (positive control --
    // this guard must reject the ambiguous cases WITHOUT rejecting the one
    // legitimate record that has no ambiguity at all).
    const rr_3 = [_]dns.Record{testARecord("a.b.c", &three_labels)};
    const signed = try buildSignedData(testing.allocator, &rr_3, zero_rrsig, "a.b.c");
    testing.allocator.free(signed);
}

test "buildSignedData: F7 -- mixing the true record with an ambiguous one in the same RRset is refused" {
    const three_labels = [_][]const u8{ "a", "b", "c" };
    const one_label = [_][]const u8{"a.b.c"};
    const mixed = [_]dns.Record{
        testARecord("a.b.c", &three_labels),
        testARecord("a.b.c", &one_label),
    };
    try testing.expectError(error.InconsistentRrset, buildSignedData(testing.allocator, &mixed, zero_rrsig, "a.b.c"));
}

test "buildSignedData: F7 -- a Record with unpopulated labels (hand-built, e.g. chain.zig's synthetic DNSKEY set) is unaffected" {
    // `labels.len == 0` means "structure unknown here", not "root name" --
    // the new guard must skip it entirely, exactly reproducing pre-fix
    // behavior for every caller that never populates `.labels`.
    const empty: []const []const u8 = &.{};
    const rr = [_]dns.Record{testARecord("a.b.c", empty)};
    const signed = try buildSignedData(testing.allocator, &rr, zero_rrsig, "a.b.c");
    defer testing.allocator.free(signed);
    // Same bytes as the genuinely-3-label case above: the guard changes
    // nothing about the OUTPUT for unpopulated `labels`, only whether an
    // ambiguous populated one is refused.
    const three_labels = [_][]const u8{ "a", "b", "c" };
    const rr_true = [_]dns.Record{testARecord("a.b.c", &three_labels)};
    const signed_true = try buildSignedData(testing.allocator, &rr_true, zero_rrsig, "a.b.c");
    defer testing.allocator.free(signed_true);
    try testing.expectEqualSlices(u8, signed_true, signed);
}
