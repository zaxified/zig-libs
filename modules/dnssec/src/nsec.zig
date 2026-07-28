// SPDX-License-Identifier: MIT

//! Plain NSEC (non-NSEC3) denial-of-existence proof validation
//! (RFC 4035 §5.4, RFC 4034 §4 + §6.1).
//!
//! The analogue of `nsec3.proveDenial`, but over the *unhashed* NSEC chain: an
//! NSEC RR at owner name `O` asserts that no name exists strictly between `O`
//! and its Next Domain Name `N` in DNSSEC canonical name order (RFC 4034 §6.1),
//! and its Type Bit Maps lists exactly the RR types present at `O`. From a set
//! of such records `proveDenial` decides whether they prove NXDOMAIN, NODATA,
//! a positive wildcard answer, or an insecure (unsigned) delegation — never
//! panicking on malformed input (every bad shape maps to `.bogus`).
//!
//! CANONICAL NAME ORDER (RFC 4034 §6.1) is the heart of the gap check and is
//! NOT byte order on the dotted text: names sort by their sequence of labels
//! read right-to-left (TLD first), each label compared as a case-folded,
//! left-justified octet string, a shorter label (proper prefix) sorting first,
//! and a name with fewer labels (an ancestor) sorting before its descendants.
//! `canonicalNameCmp` implements exactly that.
//!
//! Scope / trust boundary (same as `nsec3.proveDenial`): this decides denial
//! from records ASSUMED already signature-validated by `validate`. It proves
//! the *logical* structure of the denial, not the authenticity of the NSEC RRs
//! themselves — a forged-but-unsigned NSEC set is caught upstream by the RRSIG
//! check, not here. What it does defend against is a semantically invalid proof
//! built from otherwise-valid records: a qname outside every gap, a bitmap that
//! actually asserts the queried type, or a wildcard that in fact exists.

const std = @import("std");
const rdata = @import("rdata.zig");
const wire = @import("wire.zig");

// ── RR type numbers referenced by the proof logic ───────────────────────────

const cname_type: u16 = 5;
const ns_type: u16 = 2;
const soa_type: u16 = 6;
const ds_type: u16 = 43;

/// Longest possible label count for a 253-octet name: labels are >= 1 octet
/// plus a separator, so 128 slots (with the guard below) always suffices.
const max_labels = 128;

// ── denial verdict (mirrors `nsec3.DenialResult`) ───────────────────────────

pub const DenialResult = enum {
    /// NXDOMAIN: an NSEC covers the qname (it provably does not exist) AND an
    /// NSEC covers the source-of-synthesis wildcard `*.<closest encloser>`
    /// (no wildcard could have answered) — RFC 4035 §5.4.
    name_error,
    /// The name exists but the queried type does not: either a direct NSEC
    /// match at the qname whose bitmap lacks the type (and CNAME), or a
    /// wildcard NSEC match whose bitmap lacks the type (RFC 4035 §5.4).
    no_data,
    /// A wildcard `*.<closest encloser>` exists and its bitmap asserts the
    /// queried type (or CNAME): a positive wildcard answer, not a denial.
    wildcard_answer,
    /// A validated NSEC proves an *unsigned* delegation: for a DS query, the
    /// NSEC at the qname has NS set but neither SOA nor DS. Per RFC 4035 §5.2 /
    /// RFC 4033 this is provably-insecure (the child zone is not signed), the
    /// NSEC analogue of NSEC3 Opt-Out.
    insecure,
    /// The supplied NSEC set is not a valid proof (no covering record,
    /// uncovered wildcard, contradictory bitmap, or malformed name) — treat
    /// like a failed denial, exactly as `nsec3.proveDenial` returns `.bogus`.
    bogus,
};

/// One NSEC RR: the owner name it sits at (dotted text) and its parsed RDATA
/// (`next_domain_name` + Type Bit Maps). Mirrors `nsec3.Nsec3Record`, but the
/// owner is a real name rather than a base32hex hash label.
pub const NsecRecord = struct {
    owner: []const u8,
    rdata: rdata.Nsec,
};

pub const NsecSet = struct {
    records: []const NsecRecord,
};

/// Prove (or disprove) denial of existence for `qname`/`qtype` against a set of
/// NSEC records (RFC 4035 §5.4). `qname` is dotted text (e.g. `mail.example`);
/// records are assumed already signature-validated (see the file header). Fails
/// closed: any malformed name or missing link yields `.bogus`, never a panic.
pub fn proveDenial(qname: []const u8, qtype: u16, nsec_set: NsecSet) DenialResult {
    const set = nsec_set.records;

    // (1) Direct NSEC match on the QNAME: the name provably EXISTS, so the only
    // denial it can support is NODATA — the queried type (and CNAME) must be
    // absent from its bitmap. RFC 4035 §5.4 (NODATA) / §4.1.1.
    if (matchNsec(set, qname)) |m| {
        if (m.contains(qtype) or m.contains(cname_type)) return .bogus;
        // Unsigned-delegation NODATA (RFC 4035 §5.2): a DS query answered by an
        // NSEC with NS but no SOA and no DS proves the child zone is insecure,
        // not a normal same-zone NODATA. This is the NSEC counterpart of the
        // NSEC3 Opt-Out downgrade.
        if (qtype == ds_type and m.contains(ns_type) and
            !m.contains(soa_type) and !m.contains(ds_type)) return .insecure;
        return .no_data;
    }

    // (2) An NSEC must COVER the qname — owner < qname < next in canonical order
    // (RFC 4034 §6.1), wrap-around included — proving qname does not exist.
    const cover = coverNsec(set, qname) orelse return .bogus;

    // (3) Closest encloser (RFC 7129 §5.5): the longer of the label-suffixes
    // that the covering NSEC's owner and next names share with the qname. The
    // wildcard that could have synthesized an answer is `*.<closest encloser>`.
    const ce = closestEncloser(cover.owner, cover.rdata.next_domain_name, qname) orelse return .bogus;
    var wc_buf: [2 + wire.max_name_text_len]u8 = undefined;
    const wildcard = wildcardName(ce, &wc_buf) orelse return .bogus;

    // (4) Resolve the wildcard against the same NSEC set:
    //   - a direct match means the wildcard EXISTS → wildcard NODATA if the
    //     type is absent, else a positive wildcard answer (RFC 4035 §5.4);
    //   - otherwise the wildcard must itself be COVERED (proving no wildcard
    //     exists) → NXDOMAIN.
    if (matchNsec(set, wildcard)) |wm| {
        if (wm.contains(qtype) or wm.contains(cname_type)) return .wildcard_answer;
        return .no_data;
    }
    _ = coverNsec(set, wildcard) orelse return .bogus;
    return .name_error;
}

// ── canonical name order (RFC 4034 §6.1) ────────────────────────────────────

fn stripDot(name: []const u8) []const u8 {
    return if (std.mem.endsWith(u8, name, ".")) name[0 .. name.len - 1] else name;
}

/// Split dotted `name` into its labels (a slice into `name`), or null if the
/// name is malformed (an empty interior label, an over-long label, or more than
/// `max_labels` labels). The root ("" or ".") yields zero labels.
fn splitLabels(name: []const u8, out: *[max_labels][]const u8) ?[]const []const u8 {
    const n = stripDot(name);
    if (n.len == 0) return out[0..0];
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, n, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > wire.max_label_len) return null;
        if (count >= max_labels) return null;
        out[count] = label;
        count += 1;
    }
    return out[0..count];
}

/// Compare two labels case-insensitively as left-justified octet strings, a
/// proper prefix sorting first (RFC 4034 §6.1).
fn labelCmp(a: []const u8, b: []const u8) std.math.Order {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const ca = std.ascii.toLower(a[i]);
        const cb = std.ascii.toLower(b[i]);
        if (ca != cb) return std.math.order(ca, cb);
    }
    return std.math.order(a.len, b.len);
}

/// DNSSEC canonical name order (RFC 4034 §6.1): compare label sequences from
/// the rightmost (TLD) label inward; on a tie the name with fewer labels (the
/// ancestor) sorts first. Returns null if either name is malformed.
fn canonicalNameCmp(a: []const u8, b: []const u8) ?std.math.Order {
    var abuf: [max_labels][]const u8 = undefined;
    var bbuf: [max_labels][]const u8 = undefined;
    const al = splitLabels(a, &abuf) orelse return null;
    const bl = splitLabels(b, &bbuf) orelse return null;
    var ai = al.len;
    var bi = bl.len;
    while (ai > 0 and bi > 0) {
        ai -= 1;
        bi -= 1;
        const o = labelCmp(al[ai], bl[bi]);
        if (o != .eq) return o;
    }
    return std.math.order(al.len, bl.len);
}

/// Number of trailing labels `a` and `b` share (case-insensitively) — the
/// length, in labels, of their longest common suffix. Malformed names share 0.
fn commonSuffixLabels(a: []const u8, b: []const u8) usize {
    var abuf: [max_labels][]const u8 = undefined;
    var bbuf: [max_labels][]const u8 = undefined;
    const al = splitLabels(a, &abuf) orelse return 0;
    const bl = splitLabels(b, &bbuf) orelse return 0;
    var ai = al.len;
    var bi = bl.len;
    var shared: usize = 0;
    while (ai > 0 and bi > 0) {
        ai -= 1;
        bi -= 1;
        if (labelCmp(al[ai], bl[bi]) != .eq) break;
        shared += 1;
    }
    return shared;
}

/// The rightmost `keep` labels of `name` as dotted text (a slice into `name`).
/// `keep == 0` (or the root) gives "".
fn lastLabels(name: []const u8, keep: usize) []const u8 {
    const n = stripDot(name);
    if (keep == 0) return n[n.len..];
    var total: usize = if (n.len == 0) 0 else 1;
    for (n) |c| {
        if (c == '.') total += 1;
    }
    if (keep >= total) return n;
    var to_drop = total - keep;
    var i: usize = 0;
    while (to_drop != 0) : (i += 1) {
        if (n[i] == '.') to_drop -= 1;
    }
    return n[i..];
}

/// The closest encloser (RFC 7129 §5.5): the longer of the label-suffixes the
/// covering NSEC's `owner` and `next` names each share with `qname`. Returns
/// null if `qname` is malformed.
fn closestEncloser(owner: []const u8, next: []const u8, qname: []const u8) ?[]const u8 {
    var qbuf: [max_labels][]const u8 = undefined;
    if (splitLabels(qname, &qbuf) == null) return null;
    const c1 = commonSuffixLabels(owner, qname);
    const c2 = commonSuffixLabels(next, qname);
    return lastLabels(qname, @max(c1, c2));
}

/// Build "*." ++ `encloser` (or "*" at the root) into `out`; null on overflow.
fn wildcardName(encloser: []const u8, out: *[2 + wire.max_name_text_len]u8) ?[]const u8 {
    var w: std.Io.Writer = .fixed(out);
    w.writeByte('*') catch return null;
    if (encloser.len != 0) {
        w.writeByte('.') catch return null;
        w.writeAll(encloser) catch return null;
    }
    return w.buffered();
}

// ── match / cover over the NSEC chain ───────────────────────────────────────

/// The Type Bit Maps of the NSEC whose owner name canonically EQUALS `name`,
/// if any (RFC 4034 §4.1.1 "match"). Records with a malformed owner are skipped.
fn matchNsec(set: []const NsecRecord, name: []const u8) ?rdata.TypeBitMap {
    for (set) |r| {
        const o = canonicalNameCmp(r.owner, name) orelse continue;
        if (o == .eq) return r.rdata.types;
    }
    return null;
}

/// The NSEC that COVERS `name`: owner < name < next in canonical order, with
/// the apex-wrapping record (owner >= next) covering name > owner OR name < next
/// (RFC 4034 §4.1.1 "cover"). Returns the whole record (owner + next are needed
/// to derive the closest encloser). Malformed records are skipped.
fn coverNsec(set: []const NsecRecord, name: []const u8) ?NsecRecord {
    for (set) |r| {
        const next = r.rdata.next_domain_name;
        const o_vs_n = canonicalNameCmp(r.owner, name) orelse continue;
        const n_vs_next = canonicalNameCmp(name, next) orelse continue;
        const owner_vs_next = canonicalNameCmp(r.owner, next) orelse continue;
        const wraps = owner_vs_next != .lt; // owner >= next: last NSEC in the zone
        const above_owner = o_vs_n == .lt; // owner < name
        const below_next = n_vs_next == .lt; // name < next
        const covered = if (wraps) (above_owner or below_next) else (above_owner and below_next);
        if (covered) return r;
    }
    return null;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Build a single-window (window 0) Type Bit Maps over `types` (all < 256) into
/// caller-owned `buf` (>= 34 bytes). Constructs `.raw` directly, exactly as the
/// NSEC3 tests do, so `contains` is exercised without a parse round-trip.
fn buildTbm(buf: []u8, types: []const u16) rdata.TypeBitMap {
    var maxb: u16 = 0;
    for (types) |t| {
        std.debug.assert(t < 256);
        if (t > maxb) maxb = t;
    }
    const nbytes: usize = maxb / 8 + 1;
    buf[0] = 0; // window 0
    buf[1] = @intCast(nbytes);
    for (buf[2 .. 2 + nbytes]) |*b| b.* = 0;
    for (types) |t| buf[2 + t / 8] |= @as(u8, 0x80) >> @intCast(t % 8);
    return .{ .raw = buf[0 .. 2 + nbytes] };
}

test "canonicalNameCmp: RFC 4034 §6.1 worked ordering" {
    // The exact ordering from RFC 4034 §6.1's example set.
    const ordered = [_][]const u8{
        "example",
        "a.example",
        "yljkjljk.a.example",
        "Z.a.example",
        "zABC.a.EXAMPLE",
        "z.example",
        "\x01.z.example", // "\001.z.example" in the RFC
        "*.z.example",
        "\xc8.z.example", // "\200.z.example"
    };
    var i: usize = 0;
    while (i + 1 < ordered.len) : (i += 1) {
        try testing.expectEqual(@as(?std.math.Order, .lt), canonicalNameCmp(ordered[i], ordered[i + 1]));
        try testing.expectEqual(@as(?std.math.Order, .gt), canonicalNameCmp(ordered[i + 1], ordered[i]));
    }
    // Case-insensitive equality of the same name.
    try testing.expectEqual(@as(?std.math.Order, .eq), canonicalNameCmp("WwW.Example.COM", "www.example.com"));
    // Ancestor sorts before descendant (fewer labels wins on a suffix tie).
    try testing.expectEqual(@as(?std.math.Order, .lt), canonicalNameCmp("example.com", "www.example.com"));
}

test "canonicalNameCmp: malformed name yields null (no panic)" {
    try testing.expectEqual(@as(?std.math.Order, null), canonicalNameCmp("a..b", "a.b"));
    const too_long = "a" ** 64; // over the 63-octet label limit
    try testing.expectEqual(@as(?std.math.Order, null), canonicalNameCmp(too_long, "a.b"));
}

test "proveDenial NXDOMAIN: qname inside the gap, wildcard covered (positive control)" {
    // Zone `example`: existing owner names sorted canonically are
    //   example  <  a.example  <  www.example
    // plus the source-of-synthesis wildcard `*.example` (which sorts between
    // `example` and `a.example`, since '*'=0x2a < 'a'). NSEC chain:
    //   example      NSEC *.example    (apex; SOA/NS/…)
    //   *.example    NSEC a.example
    //   a.example    NSEC www.example
    //   www.example  NSEC example      (wrap)
    // Query mail.example / A: covered by the `a.example -> www.example` gap,
    // and the wildcard `*.example` exists but... here we want plain NXDOMAIN,
    // so make the wildcard NOT exist: drop `*.example` and let `example` NSEC
    // to `a.example`, so the wildcard is COVERED, not matched.
    var b_apex: [34]u8 = undefined;
    var b_a: [34]u8 = undefined;
    var b_www: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "example", .rdata = .{ .next_domain_name = "a.example", .types = buildTbm(&b_apex, &.{ soa_type, ns_type }) } },
        .{ .owner = "a.example", .rdata = .{ .next_domain_name = "www.example", .types = buildTbm(&b_a, &.{1}) } },
        .{ .owner = "www.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b_www, &.{1}) } },
    };
    // mail.example is between a.example and www.example → covered; wildcard
    // *.example is between example and a.example → covered → NXDOMAIN.
    try testing.expectEqual(DenialResult.name_error, proveDenial("mail.example", 1, .{ .records = &set }));
}

test "proveDenial NXDOMAIN: RED if gap-coverage is honored — qname just outside the gap is bogus" {
    // Same chain as above. `zzz.example` sorts AFTER www.example, so only the
    // wrap record covers it — but then the closest encloser is `example` and
    // the wildcard `*.example` is covered by the apex NSEC too, so this would
    // actually be a valid NXDOMAIN. To get a genuine "outside every gap" case,
    // query a name that lands exactly on an owner boundary: `a.example` EXISTS
    // (it is an owner), so it must NOT be provable as NXDOMAIN.
    var b_apex: [34]u8 = undefined;
    var b_a: [34]u8 = undefined;
    var b_www: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "example", .rdata = .{ .next_domain_name = "a.example", .types = buildTbm(&b_apex, &.{ soa_type, ns_type }) } },
        .{ .owner = "a.example", .rdata = .{ .next_domain_name = "www.example", .types = buildTbm(&b_a, &.{1}) } },
        .{ .owner = "www.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b_www, &.{1}) } },
    };
    // a.example exists (matched, type A present) → cannot be NXDOMAIN; querying
    // a type it HAS is not a denial at all → bogus.
    try testing.expectEqual(DenialResult.bogus, proveDenial("a.example", 1, .{ .records = &set }));

    // The assertion above only exercises the MATCH path (owner-name equality +
    // bitmap), so it passes unchanged against an implementation whose cover
    // check is a no-op ("any NSEC covers any name") — verified by mutation.
    // Teeth for the gap check proper: take the same chain minus its wrapping
    // record, so `zzz.example` (which sorts after every owner) falls outside
    // every remaining gap. Only a real owner<name<next test can tell this from
    // the covered case in the positive control above.
    const truncated = set[0..2].*;
    try testing.expectEqual(DenialResult.bogus, proveDenial("zzz.example", 1, .{ .records = &truncated }));
}

test "proveDenial NXDOMAIN: forged next-name that does not cover the qname is bogus" {
    // A single NSEC whose gap does not contain the qname cannot prove NXDOMAIN.
    var b_a: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "a.example", .rdata = .{ .next_domain_name = "b.example", .types = buildTbm(&b_a, &.{1}) } },
    };
    // zzz.example is not in (a.example, b.example) and there is no wrap record
    // reaching it → no cover → bogus.
    try testing.expectEqual(DenialResult.bogus, proveDenial("zzz.example", 1, .{ .records = &set }));
}

test "proveDenial NODATA: direct match, queried type absent" {
    // www.example exists with A + RRSIG + NSEC; a query for AAAA(28) is NODATA.
    var b_www: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "www.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b_www, &.{ 1, 46, 47 }) } },
    };
    try testing.expectEqual(DenialResult.no_data, proveDenial("www.example", 28, .{ .records = &set }));
}

test "proveDenial NODATA: RED if the bitmap check is honored — wrong-type-in-bitmap is bogus" {
    // Same record, but now query A(1), which the bitmap DOES assert present:
    // the NSEC cannot deny a type it lists → bogus (would be a false NODATA if
    // the bitmap check were dropped).
    var b_www: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "www.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b_www, &.{ 1, 46, 47 }) } },
    };
    try testing.expectEqual(DenialResult.bogus, proveDenial("www.example", 1, .{ .records = &set }));
}

test "proveDenial NODATA: CNAME present makes a NODATA proof bogus" {
    // A name with a CNAME should have been chased; an NSEC listing CNAME cannot
    // authoritatively deny another type at that name (RFC 4035 §5.4).
    var b: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "alias.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b, &.{ cname_type, 46, 47 }) } },
    };
    try testing.expectEqual(DenialResult.bogus, proveDenial("alias.example", 28, .{ .records = &set }));
}

test "proveDenial: wrap-around at the zone apex covers a trailing name" {
    // Zone with a single delegation-free span: apex `example` NSEC to
    // `a.example`, and `a.example` NSEC wraps back to `example`. A name sorting
    // after `a.example`, e.g. `z.example`, is covered only by the wrap record;
    // the wildcard `*.example` (between example and a.example) is covered by the
    // apex NSEC → NXDOMAIN. Removing the wrap handling would drop the cover and
    // yield bogus, so this exercises the wrap branch specifically.
    var b_apex: [34]u8 = undefined;
    var b_a: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "example", .rdata = .{ .next_domain_name = "a.example", .types = buildTbm(&b_apex, &.{ soa_type, ns_type }) } },
        .{ .owner = "a.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b_a, &.{1}) } },
    };
    try testing.expectEqual(DenialResult.name_error, proveDenial("z.example", 1, .{ .records = &set }));
}

test "proveDenial wildcard-NODATA: wildcard exists but lacks the queried type" {
    // `*.example` exists (owner match) with only A; qname `foo.example` does not
    // exist (covered) so the wildcard would synthesize — but for AAAA(28) the
    // wildcard has no data → wildcard NODATA.
    var b_apex: [34]u8 = undefined;
    var b_star: [34]u8 = undefined;
    var b_a: [34]u8 = undefined;
    // Canonical order: example < *.example < a.example  (since '*'=0x2a < 'a').
    const set = [_]NsecRecord{
        .{ .owner = "example", .rdata = .{ .next_domain_name = "*.example", .types = buildTbm(&b_apex, &.{ soa_type, ns_type }) } },
        .{ .owner = "*.example", .rdata = .{ .next_domain_name = "a.example", .types = buildTbm(&b_star, &.{1}) } },
        .{ .owner = "a.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b_a, &.{1}) } },
    };
    // foo.example sorts after a.example (wrap covers it): closest encloser is
    // `example`, wildcard `*.example` matches with only A → AAAA is NODATA.
    try testing.expectEqual(DenialResult.no_data, proveDenial("foo.example", 28, .{ .records = &set }));
    // ...and querying A(1), which the wildcard DOES have, is a positive
    // wildcard answer, not a denial.
    try testing.expectEqual(DenialResult.wildcard_answer, proveDenial("foo.example", 1, .{ .records = &set }));
}

test "proveDenial: insecure delegation — DS NODATA with NS set, no SOA, no DS" {
    // A delegation point `child.example` carries NS (+RRSIG+NSEC) but no SOA and
    // no DS. A DS(43) query there proves the child is an UNSIGNED delegation →
    // insecure, the NSEC analogue of NSEC3 Opt-Out.
    var b: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "child.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b, &.{ ns_type, 46, 47 }) } },
    };
    try testing.expectEqual(DenialResult.insecure, proveDenial("child.example", ds_type, .{ .records = &set }));
    // The same NSEC for a non-DS query (e.g. A) is an ordinary NODATA.
    try testing.expectEqual(DenialResult.no_data, proveDenial("child.example", 1, .{ .records = &set }));
}

test "proveDenial: empty set and malformed qname fail closed to bogus (no panic)" {
    const empty: NsecSet = .{ .records = &[_]NsecRecord{} };
    try testing.expectEqual(DenialResult.bogus, proveDenial("www.example", 1, empty));
    // Malformed qname (empty interior label) cannot match or be covered.
    var b: [34]u8 = undefined;
    const set = [_]NsecRecord{
        .{ .owner = "a.example", .rdata = .{ .next_domain_name = "example", .types = buildTbm(&b, &.{1}) } },
    };
    try testing.expectEqual(DenialResult.bogus, proveDenial("a..example", 1, .{ .records = &set }));
}
