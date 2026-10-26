// SPDX-License-Identifier: MIT

//! Live oracle for `x509`: Go's crypto/x509 (the scope reference, through its
//! public API in `tools/go_oracle`) judges every case, and each verdict is
//! compared with this module's `verifyChain` / `hostname.verify` under the
//! options Go's call corresponds to.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-x509` runs it and
//! `zig build check-interop` compiles it. Needs `go` on PATH (stdlib only, no
//! module downloads; GOPROXY=off). Run from the repository root.
//!
//!   zig build interop-x509                 # judge and compare; exit 1 on any surprise
//!   zig build interop-x509 -- --seed N     # another draw of the generated families
//!   zig build interop-x509 -- --write      # also rewrite src/data/s2/leads.bin
//!
//! Two sources of cases:
//!
//! - **corpus**: every record of the committed S2 corpus
//!   (`src/data/s2/corpus.bin`, replayed without Go by `s2_oracle_test.zig`)
//!   is judged by the Go on PATH again. A verdict that differs from the one
//!   frozen in the corpus is a surprise too: the frozen copy went stale.
//! - **generated**: certificates built here (own DER writer, ECDSA P-256 keys
//!   from fixed seeds, std's deterministic signatures), in families drawn from
//!   a PRNG: name constraints of every type Go checks against every SAN type,
//!   validity boundaries, hostnames against wildcard/IP/odd SANs, EKU and
//!   pathLen combinations. And the directoryName rows: Go does not process
//!   directoryName constraints, so a leaf whose subject or SAN directoryName
//!   falls outside them is accepted by Go and refused here (RFC 5280
//!   §4.2.1.10, §6.1.3 (b)/(c)).
//!
//! Each case carries an expectation: `agree` (both accept or both reject) or
//! `stricter` (this module refuses what Go accepts, on the rule in `why` --
//! the rows behind the card's `**Ahead:**` line). A row that changes either
//! way fails the run. `--write` freezes the generated lead rows (DER, Go's
//! verdict, the expectation) into `src/data/s2/leads.bin`, which
//! `s2_oracle_test.zig` replays in `test-x509` without Go; they do not depend
//! on the seed (fixed keys, deterministic signatures). Every verdict is written to
//! `.zig-cache/interop-x509/verdicts.tsv`; stdout gets the surprises and a
//! summary per family.

const std = @import("std");
const x509 = @import("x509");
const bench = @import("testkit").bench;

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Allocator = std.mem.Allocator;

const work_dir = ".zig-cache/interop-x509";
const go_dir = "modules/x509/tools/go_oracle";
const corpus_path = "modules/x509/src/data/s2/corpus.bin";
const leads_path = "modules/x509/src/data/s2/leads.bin";

/// Fixed times, no wall clock: 2025-01-01, 2035-01-01, verify at 2026-06-01.
const t_nb: i64 = 1735689600;
const t_na: i64 = 2051222400;
const t_verify: i64 = 1780272000;

// ── expectations ─────────────────────────────────────────────────────────

const Expect = enum {
    agree,
    /// This module refuses what Go accepts, on the rule in `why`.
    stricter,
    /// Go refuses a critical extension it does not process; this module
    /// processes it and accepts.
    processes,
};

const Mode = enum { verify, hostname };

const Case = struct {
    id: []const u8,
    family: []const u8,
    mode: Mode = .verify,
    roots: []const []const u8 = &.{},
    inters: []const []const u8 = &.{},
    leaf: []const u8,
    time: i64 = t_verify,
    /// Verify mode: Go's `DNSName` = our `expected_host`.
    dns_name: ?[]const u8 = null,
    /// bit0 serverAuth, bit1 clientAuth, bit2 any; 0 = Go's default (serverAuth).
    usages: u8 = 0,
    /// The caller's acceptable policies, DER OID contents.
    policies: []const []const u8 = &.{},
    host: []const u8 = "",
    expect: Expect = .agree,
    why: []const u8 = "",
    /// Corpus records: Go's verdict as frozen in corpus.bin.
    frozen_go: ?bool = null,
};

const Verdict = struct { ok: bool, err: []const u8 };

// ── DER writer ───────────────────────────────────────────────────────────

const Der = struct {
    a: Allocator,

    fn tlv(d: Der, tag: u8, parts: []const []const u8) ![]const u8 {
        var n: usize = 0;
        for (parts) |p| n += p.len;
        var out: std.ArrayList(u8) = .empty;
        try out.append(d.a, tag);
        if (n < 0x80) {
            try out.append(d.a, @intCast(n));
        } else if (n < 0x100) {
            try out.appendSlice(d.a, &.{ 0x81, @intCast(n) });
        } else {
            std.debug.assert(n < 0x10000);
            try out.appendSlice(d.a, &.{ 0x82, @intCast(n >> 8), @truncate(n) });
        }
        for (parts) |p| try out.appendSlice(d.a, p);
        return out.items;
    }
    fn seq(d: Der, parts: []const []const u8) ![]const u8 {
        return d.tlv(0x30, parts);
    }
    fn oid(d: Der, content: []const u8) ![]const u8 {
        return d.tlv(0x06, &.{content});
    }
    fn int(d: Der, v: u32) ![]const u8 {
        var be: [5]u8 = undefined;
        be[0] = 0;
        std.mem.writeInt(u32, be[1..5], v, .big);
        var i: usize = 0;
        // Minimal two's complement: drop a leading 0x00 unless the next byte's top bit is set.
        while (i < 4 and be[i] == 0 and be[i + 1] & 0x80 == 0) i += 1;
        return d.tlv(0x02, &.{be[i..]});
    }
    fn utcTime(d: Der, unix: i64) ![]const u8 {
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix) };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        std.debug.assert(yd.year >= 1950 and yd.year < 2050);
        const s = try std.fmt.allocPrint(d.a, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            yd.year % 100,        md.month.numeric(),      md.day_index + 1,
            ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        });
        return d.tlv(0x17, &.{s});
    }
};

const oid_cn = [_]u8{ 0x55, 0x04, 0x03 };
const oid_o = [_]u8{ 0x55, 0x04, 0x0a };
const oid_ou = [_]u8{ 0x55, 0x04, 0x0b };
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
const oid_bc = [_]u8{ 0x55, 0x1d, 0x13 };
const oid_ku = [_]u8{ 0x55, 0x1d, 0x0f };
const oid_eku = [_]u8{ 0x55, 0x1d, 0x25 };
const oid_san = [_]u8{ 0x55, 0x1d, 0x11 };
const oid_nc = [_]u8{ 0x55, 0x1d, 0x1e };
const oid_server_auth = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
const oid_client_auth = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
const oid_any_eku = [_]u8{ 0x55, 0x1d, 0x25, 0x00 };

/// One attribute per RDN, in order.
const Rdn = struct { oid: []const u8, value: []const u8 };

fn name(d: Der, rdns: []const Rdn) ![]const u8 {
    const sets = try d.a.alloc([]const u8, rdns.len);
    for (rdns, sets) |r, *s| s.* = try d.tlv(0x31, &.{try d.seq(&.{ try d.oid(r.oid), try d.tlv(0x0c, &.{r.value}) })});
    return d.seq(sets);
}

const GeneralName = union(enum) {
    dns: []const u8,
    email: []const u8,
    uri: []const u8,
    /// 4 or 16 bytes; in a constraint, address then mask (8 or 32 bytes).
    ip: []const u8,
    /// A Name (DER, with its SEQUENCE header).
    dir: []const u8,

    fn der(g: GeneralName, d: Der) ![]const u8 {
        return switch (g) {
            .dns => |v| d.tlv(0x82, &.{v}),
            .email => |v| d.tlv(0x81, &.{v}),
            .uri => |v| d.tlv(0x86, &.{v}),
            .ip => |v| d.tlv(0x87, &.{v}),
            .dir => |v| d.tlv(0xa4, &.{v}),
        };
    }
};

fn extension(d: Der, oid: []const u8, critical: bool, value: []const u8) ![]const u8 {
    if (critical) return d.seq(&.{ try d.oid(oid), try d.tlv(0x01, &.{&.{0xff}}), try d.tlv(0x04, &.{value}) });
    return d.seq(&.{ try d.oid(oid), try d.tlv(0x04, &.{value}) });
}

fn extBc(d: Der, ca: bool, path_len: ?u32) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    if (ca) try parts.append(d.a, try d.tlv(0x01, &.{&.{0xff}}));
    if (path_len) |n| try parts.append(d.a, try d.int(n));
    return extension(d, &oid_bc, true, try d.seq(parts.items));
}

fn extKuCa(d: Der) ![]const u8 {
    // keyCertSign (5) + cRLSign (6): 0x06, one unused bit.
    return extension(d, &oid_ku, true, try d.tlv(0x03, &.{&.{ 0x01, 0x06 }}));
}

fn extKuLeaf(d: Der) ![]const u8 {
    // digitalSignature (0): 0x80, seven unused bits.
    return extension(d, &oid_ku, true, try d.tlv(0x03, &.{&.{ 0x07, 0x80 }}));
}

fn extSan(d: Der, names: []const GeneralName) ![]const u8 {
    const parts = try d.a.alloc([]const u8, names.len);
    for (names, parts) |g, *p| p.* = try g.der(d);
    return extension(d, &oid_san, false, try d.seq(parts));
}

/// bit0 serverAuth, bit1 clientAuth, bit2 anyExtendedKeyUsage.
fn extEku(d: Der, bits: u8) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    if (bits & 1 != 0) try parts.append(d.a, try d.oid(&oid_server_auth));
    if (bits & 2 != 0) try parts.append(d.a, try d.oid(&oid_client_auth));
    if (bits & 4 != 0) try parts.append(d.a, try d.oid(&oid_any_eku));
    return extension(d, &oid_eku, false, try d.seq(parts.items));
}

fn extNc(d: Der, permitted: []const GeneralName, excluded: []const GeneralName, critical: bool) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    inline for (.{ .{ 0xa0, permitted }, .{ 0xa1, excluded } }) |pe| {
        if (pe[1].len != 0) {
            const subtrees = try d.a.alloc([]const u8, pe[1].len);
            for (pe[1], subtrees) |g, *s| s.* = try d.seq(&.{try g.der(d)});
            try parts.append(d.a, try d.tlv(pe[0], subtrees));
        }
    }
    return extension(d, &oid_nc, critical, try d.seq(parts.items));
}

// ── certificates ─────────────────────────────────────────────────────────

const Keys = struct {
    root: Ecdsa.KeyPair,
    inter: Ecdsa.KeyPair,
    inter2: Ecdsa.KeyPair,
    leaf: Ecdsa.KeyPair,

    fn init() !Keys {
        return .{
            .root = try Ecdsa.KeyPair.generateDeterministic(@splat(0x51)),
            .inter = try Ecdsa.KeyPair.generateDeterministic(@splat(0x52)),
            .inter2 = try Ecdsa.KeyPair.generateDeterministic(@splat(0x54)),
            .leaf = try Ecdsa.KeyPair.generateDeterministic(@splat(0x53)),
        };
    }
};

const CertSpec = struct {
    subject: []const u8,
    issuer: []const u8,
    key: *const Ecdsa.KeyPair,
    signer: *const Ecdsa.KeyPair,
    exts: []const []const u8,
    nb: i64 = t_nb,
    na: i64 = t_na,
};

const Builder = struct {
    d: Der,
    k: *const Keys,
    serial: u32 = 0x1000,
    root_dn: []const u8,
    inter_dn: []const u8,
    inter2_dn: []const u8,
    leaf_dn: []const u8,

    fn init(a: Allocator, k: *const Keys) !Builder {
        const d: Der = .{ .a = a };
        return .{
            .d = d,
            .k = k,
            .root_dn = try name(d, &.{.{ .oid = &oid_cn, .value = "Interop Root" }}),
            .inter_dn = try name(d, &.{.{ .oid = &oid_cn, .value = "Interop Inter" }}),
            .inter2_dn = try name(d, &.{.{ .oid = &oid_cn, .value = "Interop Inter 2" }}),
            .leaf_dn = try name(d, &.{.{ .oid = &oid_cn, .value = "leaf cert" }}),
        };
    }

    fn cert(bd: *Builder, s: CertSpec) ![]const u8 {
        const d = bd.d;
        bd.serial += 1;
        const alg = try d.seq(&.{try d.oid(&oid_ecdsa_sha256)});
        const pub_point = s.key.public_key.toUncompressedSec1();
        const spki = try d.seq(&.{
            try d.seq(&.{ try d.oid(&oid_ec_public_key), try d.oid(&oid_prime256v1) }),
            try d.tlv(0x03, &.{ &.{0x00}, &pub_point }),
        });
        var parts: std.ArrayList([]const u8) = .empty;
        try parts.appendSlice(d.a, &.{
            try d.tlv(0xa0, &.{try d.int(2)}),
            try d.int(bd.serial),
            alg,
            s.issuer,
            try d.seq(&.{ try d.utcTime(s.nb), try d.utcTime(s.na) }),
            s.subject,
            spki,
        });
        if (s.exts.len != 0) try parts.append(d.a, try d.tlv(0xa3, &.{try d.seq(s.exts)}));
        const tbs = try d.seq(parts.items);
        const sig = try s.signer.sign(tbs, null);
        var sig_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const sig_der = sig.toDer(&sig_buf);
        return d.seq(&.{ tbs, alg, try d.tlv(0x03, &.{ &.{0x00}, sig_der }) });
    }

    const ChainSpec = struct {
        root_exts: ?[]const []const u8 = null,
        inter_exts: ?[]const []const u8 = null,
        /// A second intermediate between `inter` and the leaf.
        inter2_exts: ?[]const []const u8 = null,
        leaf_exts: ?[]const []const u8 = null,
        leaf_dn: ?[]const u8 = null,
        root_validity: [2]i64 = .{ t_nb, t_na },
        inter_validity: [2]i64 = .{ t_nb, t_na },
        leaf_validity: [2]i64 = .{ t_nb, t_na },
    };

    const Chain = struct { roots: []const []const u8, inters: []const []const u8, leaf: []const u8 };

    fn chain(bd: *Builder, c: ChainSpec) !Chain {
        const d = bd.d;
        const k = bd.k;
        const ca_default: []const []const u8 = &.{ try extBc(d, true, null), try extKuCa(d) };
        const root = try bd.cert(.{
            .subject = bd.root_dn,
            .issuer = bd.root_dn,
            .key = &k.root,
            .signer = &k.root,
            .exts = c.root_exts orelse ca_default,
            .nb = c.root_validity[0],
            .na = c.root_validity[1],
        });
        const inter = try bd.cert(.{
            .subject = bd.inter_dn,
            .issuer = bd.root_dn,
            .key = &k.inter,
            .signer = &k.root,
            .exts = c.inter_exts orelse ca_default,
            .nb = c.inter_validity[0],
            .na = c.inter_validity[1],
        });
        var inters: std.ArrayList([]const u8) = .empty;
        try inters.append(d.a, inter);
        var leaf_issuer_dn = bd.inter_dn;
        var leaf_signer = &k.inter;
        if (c.inter2_exts) |e2| {
            try inters.append(d.a, try bd.cert(.{ .subject = bd.inter2_dn, .issuer = bd.inter_dn, .key = &k.inter2, .signer = &k.inter, .exts = e2 }));
            leaf_issuer_dn = bd.inter2_dn;
            leaf_signer = &k.inter2;
        }
        const leaf_default: []const []const u8 = &.{ try extSan(d, &.{.{ .dns = "example.com" }}), try extKuLeaf(d) };
        const leaf = try bd.cert(.{
            .subject = c.leaf_dn orelse bd.leaf_dn,
            .issuer = leaf_issuer_dn,
            .key = &k.leaf,
            .signer = leaf_signer,
            .exts = c.leaf_exts orelse leaf_default,
            .nb = c.leaf_validity[0],
            .na = c.leaf_validity[1],
        });
        const roots = try d.a.dupe([]const u8, &.{root});
        return .{ .roots = roots, .inters = inters.items, .leaf = leaf };
    }
};

// ── the corpus ───────────────────────────────────────────────────────────

/// The ids `s2_oracle_test.zig` lists in `deliberate`, with its reason.
const corpus_deliberate = [_]struct { id: []const u8, why: []const u8 }{
    .{ .id = "wild-s1-h1", .why = "*.com wildcard: RFC 9525 §6.3 leaves a wildcard over a public suffix to the client; refused (OpenSSL too)" },
    .{ .id = "wild-s1-h3", .why = "*.com wildcard: RFC 9525 §6.3 leaves a wildcard over a public suffix to the client; refused (OpenSSL too)" },
};

const CorpusReader = struct {
    b: []const u8,
    i: usize = 0,

    fn bytes(r: *CorpusReader, n: usize) ![]const u8 {
        if (r.b.len - r.i < n) return error.BadCorpus;
        defer r.i += n;
        return r.b[r.i..][0..n];
    }
    fn int(r: *CorpusReader, comptime T: type) !T {
        return std.mem.readInt(T, (try r.bytes(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
    fn der(r: *CorpusReader) ![]const u8 {
        return r.bytes(try r.int(u16));
    }
};

/// Format: the comment block of `tools/gen_names_fixtures.py`.
fn corpusCases(a: Allocator, io: std.Io, out: *std.ArrayList(Case)) !void {
    const blob = try std.Io.Dir.cwd().readFileAlloc(io, corpus_path, a, .limited(1 << 22));
    var r: CorpusReader = .{ .b = blob };
    const magic = try r.bytes(8);
    if (!std.mem.eql(u8, magic, "X509S2\x00\x02")) return error.BadCorpus;
    const count = try r.int(u32);
    for (0..count) |_| {
        const id = try r.bytes(try r.int(u8));
        const mode = try r.int(u8);
        const time = try r.int(i64);
        const host = try r.bytes(try r.int(u8));
        const usages = try r.int(u8);
        const policies = try a.alloc([]const u8, try r.int(u8));
        for (policies) |*p| p.* = try r.bytes(try r.int(u8));
        const go_ok = try r.int(u8) == 1;
        const roots = try a.alloc([]const u8, try r.int(u8));
        const inters = try a.alloc([]const u8, try r.int(u8));
        for (roots) |*x| x.* = try r.der();
        for (inters) |*x| x.* = try r.der();
        const leaf = try r.der();
        var c: Case = .{
            .id = id,
            .family = "corpus",
            .mode = if (mode == 0) .verify else .hostname,
            .roots = roots,
            .inters = inters,
            .leaf = leaf,
            .time = time,
            .usages = usages,
            .policies = policies,
            .frozen_go = go_ok,
        };
        if (c.mode == .verify) {
            if (host.len != 0) c.dns_name = host;
        } else c.host = host;
        for (corpus_deliberate) |dl| if (std.mem.eql(u8, dl.id, id)) {
            c.expect = .stricter;
            c.why = dl.why;
        };
        try out.append(a, c);
    }
    if (r.i != blob.len) return error.BadCorpus;
}

// ── generated families ───────────────────────────────────────────────────

const Gen = struct {
    a: Allocator,
    bd: *Builder,
    rng: std.Random,
    out: *std.ArrayList(Case),

    fn add(g: *Gen, c: Case) !void {
        try g.out.append(g.a, c);
    }
    fn id(g: *Gen, comptime fmt: []const u8, args: anytype) ![]const u8 {
        return std.fmt.allocPrint(g.a, fmt, args);
    }
    fn pick(g: *Gen, comptime T: type, items: []const T) T {
        return items[g.rng.uintLessThan(usize, items.len)];
    }
    fn verifyCase(g: *Gen, cid: []const u8, family: []const u8, ch: Builder.Chain) Case {
        _ = g;
        return .{ .id = cid, .family = family, .roots = ch.roots, .inters = ch.inters, .leaf = ch.leaf };
    }
};

/// directoryName constraints: the lead. Go 1.26 does not process them
/// (`go doc x509.Certificate.Verify`: DNS, email, IP, URI only).
fn genDirName(g: *Gen) !void {
    const d = g.bd.d;
    const good = try name(d, &.{.{ .oid = &oid_o, .value = "Good Org" }});
    const evil = try name(d, &.{.{ .oid = &oid_o, .value = "Evil Org" }});
    const good_unit = try name(d, &.{ .{ .oid = &oid_o, .value = "Good Org" }, .{ .oid = &oid_ou, .value = "Unit" } });
    const leaf_good = try name(d, &.{ .{ .oid = &oid_o, .value = "Good Org" }, .{ .oid = &oid_cn, .value = "leaf cert" } });
    const leaf_evil = try name(d, &.{ .{ .oid = &oid_o, .value = "Evil Org" }, .{ .oid = &oid_cn, .value = "leaf cert" } });
    const leaf_good_unit = try name(d, &.{ .{ .oid = &oid_o, .value = "Good Org" }, .{ .oid = &oid_ou, .value = "Unit" }, .{ .oid = &oid_cn, .value = "leaf cert" } });
    const outside_subject = "RFC 5280 §4.2.1.10 + §6.1.3 (b)/(c): the subject DN must lie within a permitted directoryName subtree and outside an excluded one; Go does not process directoryName constraints";
    const outside_san = "RFC 5280 §4.2.1.10: a subjectAltName directoryName is checked against directoryName constraints; Go does not process them";

    const Row = struct {
        id: []const u8,
        permitted: []const GeneralName = &.{},
        excluded: []const GeneralName = &.{},
        leaf_dn: []const u8,
        san_dir: ?[]const u8 = null,
        expect: Expect,
        why: []const u8 = "",
    };
    const rows = [_]Row{
        .{ .id = "dn-perm-in", .permitted = &.{.{ .dir = good }}, .leaf_dn = leaf_good, .expect = .agree, .why = "subject under the permitted O" },
        .{ .id = "dn-perm-in-deeper", .permitted = &.{.{ .dir = good }}, .leaf_dn = leaf_good_unit, .expect = .agree, .why = "subject deeper under the permitted O" },
        .{ .id = "dn-perm-out", .permitted = &.{.{ .dir = good }}, .leaf_dn = leaf_evil, .expect = .stricter, .why = outside_subject },
        .{ .id = "dn-perm-unit-out", .permitted = &.{.{ .dir = good_unit }}, .leaf_dn = leaf_good, .expect = .stricter, .why = outside_subject },
        .{ .id = "dn-excl-hit", .excluded = &.{.{ .dir = evil }}, .leaf_dn = leaf_evil, .expect = .stricter, .why = outside_subject },
        .{ .id = "dn-excl-miss", .excluded = &.{.{ .dir = evil }}, .leaf_dn = leaf_good, .expect = .agree, .why = "subject outside the excluded O" },
        .{ .id = "dn-perm-san-out", .permitted = &.{.{ .dir = good }}, .leaf_dn = leaf_good, .san_dir = evil, .expect = .stricter, .why = outside_san },
        .{ .id = "dn-excl-san-hit", .excluded = &.{.{ .dir = evil }}, .leaf_dn = leaf_good, .san_dir = evil, .expect = .stricter, .why = outside_san },
        .{ .id = "dn-perm-san-in", .permitted = &.{.{ .dir = good }}, .leaf_dn = leaf_good, .san_dir = good_unit, .expect = .agree, .why = "SAN directoryName under the permitted O" },
    };
    for (rows) |r| for ([_]bool{ true, false }) |critical| {
        var san: std.ArrayList(GeneralName) = .empty;
        try san.append(g.a, .{ .dns = "example.com" });
        if (r.san_dir) |sd| try san.append(g.a, .{ .dir = sd });
        const ch = try g.bd.chain(.{
            .inter_exts = &.{ try extBc(d, true, null), try extKuCa(d), try extNc(d, r.permitted, r.excluded, critical) },
            .leaf_exts = &.{ try extSan(d, san.items), try extKuLeaf(d) },
            .leaf_dn = r.leaf_dn,
        });
        var c = g.verifyCase(try g.id("{s}{s}", .{ r.id, if (critical) "" else "-noncrit" }), "dirname", ch);
        // Critical, Go refuses the chain as an unhandled critical extension.
        c.expect = if (!critical) r.expect else if (r.expect == .stricter) .agree else .processes;
        c.why = if (critical and r.expect != .stricter) "a critical nameConstraints with a directoryName subtree: Go refuses it as unhandled, this module processes it (RFC 5280 §4.2: a critical extension the verifier recognises is processed)" else r.why;
        try g.add(c);
    };
}

/// Name constraints of the four types Go checks, against SANs of every type,
/// drawn at random: permitted and/or excluded, one or two subtrees, one to
/// three SANs.
fn genNameConstraints(g: *Gen, n: usize) !void {
    const d = g.bd.d;
    const dns_bases = [_][]const u8{ "example.com", ".example.com", "a.example.com", "EXAMPLE.COM", "com", "", "example.org", "b.a.example.com" };
    const email_bases = [_][]const u8{ "example.com", ".example.com", "user@example.com", "a.example.com", "User@example.com", "example.org" };
    const uri_bases = [_][]const u8{ "example.com", ".example.com", "a.example.com", "EXAMPLE.com" };
    const ip_bases = [_][]const u8{
        &[8]u8{ 10, 0, 0, 0, 255, 0, 0, 0 },
        &[8]u8{ 192, 168, 1, 0, 255, 255, 255, 0 },
        &[8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
        &[32]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    const dns_sans = [_][]const u8{ "example.com", "a.example.com", "b.a.example.com", "xexample.com", "EXAMPLE.com", "example.org", "a.example.org", "A.Example.Com" };
    const email_sans = [_][]const u8{ "user@example.com", "USER@example.com", "user@EXAMPLE.com", "user@a.example.com", "other@example.com", "user@example.org" };
    const uri_sans = [_][]const u8{ "https://example.com/", "https://a.example.com/x", "https://EXAMPLE.com", "https://example.org/", "https://example.com:8443/p", "https://b.a.example.com" };
    const ip_sans = [_][]const u8{
        &[4]u8{ 10, 1, 2, 3 },                                                 &[4]u8{ 11, 0, 0, 1 },
        &[4]u8{ 192, 168, 1, 7 },                                              &[4]u8{ 192, 168, 2, 1 },
        &[16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &[16]u8{ 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    };

    for (0..n) |i| {
        var permitted: std.ArrayList(GeneralName) = .empty;
        var excluded: std.ArrayList(GeneralName) = .empty;
        const subtrees = 1 + g.rng.uintLessThan(usize, 2);
        for (0..subtrees) |_| {
            const gn: GeneralName = switch (g.rng.uintLessThan(u8, 4)) {
                0 => .{ .dns = g.pick([]const u8, &dns_bases) },
                1 => .{ .email = g.pick([]const u8, &email_bases) },
                2 => .{ .uri = g.pick([]const u8, &uri_bases) },
                else => .{ .ip = g.pick([]const u8, &ip_bases) },
            };
            if (g.rng.boolean()) try permitted.append(g.a, gn) else try excluded.append(g.a, gn);
        }
        var sans: std.ArrayList(GeneralName) = .empty;
        const n_sans = 1 + g.rng.uintLessThan(usize, 3);
        for (0..n_sans) |_| {
            try sans.append(g.a, switch (g.rng.uintLessThan(u8, 4)) {
                0 => .{ .dns = g.pick([]const u8, &dns_sans) },
                1 => .{ .email = g.pick([]const u8, &email_sans) },
                2 => .{ .uri = g.pick([]const u8, &uri_sans) },
                else => .{ .ip = g.pick([]const u8, &ip_sans) },
            });
        }
        const ch = try g.bd.chain(.{
            .inter_exts = &.{ try extBc(d, true, null), try extKuCa(d), try extNc(d, permitted.items, excluded.items, true) },
            .leaf_exts = &.{ try extSan(d, sans.items), try extKuLeaf(d) },
        });
        try g.add(g.verifyCase(try g.id("nc-{d}", .{i}), "name-constraints", ch));
    }
}

/// Validity: one second either side of every notBefore / notAfter on the chain.
fn genValidity(g: *Gen) !void {
    const day = 86400;
    const root_v = [2]i64{ t_nb - 400 * day, t_na + 400 * day };
    const inter_v = [2]i64{ t_nb - 200 * day, t_na + 200 * day };
    const leaf_v = [2]i64{ t_nb, t_nb + 700 * day };
    const ch = try g.bd.chain(.{ .root_validity = root_v, .inter_validity = inter_v, .leaf_validity = leaf_v });
    const marks = [_]struct { what: []const u8, t: i64 }{
        .{ .what = "root-nb", .t = root_v[0] },   .{ .what = "root-na", .t = root_v[1] },
        .{ .what = "inter-nb", .t = inter_v[0] }, .{ .what = "inter-na", .t = inter_v[1] },
        .{ .what = "leaf-nb", .t = leaf_v[0] },   .{ .what = "leaf-na", .t = leaf_v[1] },
    };
    for (marks) |m| for ([_]i64{ -1, 0, 1 }) |delta| {
        var c = g.verifyCase(try g.id("validity-{s}{d}", .{ m.what, delta }), "validity", ch);
        c.time = m.t + delta;
        try g.add(c);
    };
}

/// Hostnames against SAN sets drawn from wildcard, IP, case and odd shapes;
/// both through `VerifyHostname` and through `Verify` with `DNSName`.
fn genHostnames(g: *Gen, n: usize) !void {
    const d = g.bd.d;
    const sans = [_]GeneralName{
        .{ .dns = "example.com" },        .{ .dns = "*.example.com" },         .{ .dns = "a.example.com" },
        .{ .dns = "*.a.example.com" },    .{ .dns = "a*.example.com" },        .{ .dns = "*" },
        .{ .dns = "EXAMPLE.org" },        .{ .dns = "xn--bcher-kva.example" }, .{ .dns = "*.*.example.com" },
        .{ .dns = "b.*.example.com" },    .{ .ip = &[4]u8{ 192, 0, 2, 1 } },   .{ .ip = &[16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
        .{ .email = "user@example.com" }, .{ .uri = "https://example.com/" },
    };
    const hosts = [_][]const u8{
        "example.com",      "a.example.com", "b.a.example.com",       "A.EXAMPLE.COM", "example.com.",
        "x.example.org",    "example.org",   "192.0.2.1",             "[2001:db8::1]", "2001:db8::1",
        "::ffff:192.0.2.1", "192.0.2.01",    "xn--bcher-kva.example", "*.example.com", "ab.example.com",
        "a.b.example.com",  "example.com..", ".example.com",          "localhost",     "user@example.com",
    };
    var leaves: [24]Builder.Chain = undefined;
    for (&leaves) |*lc| {
        var set: std.ArrayList(GeneralName) = .empty;
        const k = 1 + g.rng.uintLessThan(usize, 3);
        for (0..k) |_| try set.append(g.a, g.pick(GeneralName, &sans));
        lc.* = try g.bd.chain(.{ .leaf_exts = &.{ try extSan(d, set.items), try extKuLeaf(d) } });
    }
    for (0..n) |i| {
        const ch = leaves[g.rng.uintLessThan(usize, leaves.len)];
        const host = g.pick([]const u8, &hosts);
        if (g.rng.boolean()) {
            try g.add(.{ .id = try g.id("host-{d}", .{i}), .family = "hostname", .mode = .hostname, .leaf = ch.leaf, .host = host });
        } else {
            var c = g.verifyCase(try g.id("dnsname-{d}", .{i}), "hostname", ch);
            c.dns_name = host;
            try g.add(c);
        }
    }
}

/// EKU on intermediate and leaf against the caller's usages, and pathLen on
/// the root and the intermediates, with one or two intermediates.
fn genEkuPathLen(g: *Gen, n: usize) !void {
    const d = g.bd.d;
    const path_lens = [_]?u32{ null, 0, 1, 2 };
    for (0..n) |i| {
        const root_pl = g.pick(?u32, &path_lens);
        const inter_pl = g.pick(?u32, &path_lens);
        const two = g.rng.boolean();
        var inter_exts: std.ArrayList([]const u8) = .empty;
        try inter_exts.appendSlice(g.a, &.{ try extBc(d, true, inter_pl), try extKuCa(d) });
        // Never empty here: `genEkuEmpty` has those rows.
        const inter_eku: ?u8 = if (g.rng.boolean()) 1 + g.rng.uintLessThan(u8, 7) else null;
        if (inter_eku) |bits| try inter_exts.append(g.a, try extEku(d, bits));
        var leaf_exts: std.ArrayList([]const u8) = .empty;
        try leaf_exts.appendSlice(g.a, &.{ try extSan(d, &.{.{ .dns = "example.com" }}), try extKuLeaf(d) });
        const leaf_eku: ?u8 = if (g.rng.boolean()) 1 + g.rng.uintLessThan(u8, 7) else null;
        if (leaf_eku) |bits| try leaf_exts.append(g.a, try extEku(d, bits));
        const ch = try g.bd.chain(.{
            .root_exts = &.{ try extBc(d, true, root_pl), try extKuCa(d) },
            .inter_exts = inter_exts.items,
            .inter2_exts = if (two) &.{ try extBc(d, true, null), try extKuCa(d) } else null,
            .leaf_exts = leaf_exts.items,
        });
        var c = g.verifyCase(try g.id("eku-pl-{d}", .{i}), "eku-pathlen", ch);
        c.usages = g.rng.uintLessThan(u8, 8);
        c.why = try g.id("root pathLen {?d}, inter pathLen {?d}, {d} intermediate(s), inter EKU {?b:0>3}, leaf EKU {?b:0>3}, usages {b:0>3} (bits: any client server)", .{ root_pl, inter_pl, @as(u8, if (two) 2 else 1), inter_eku, leaf_eku, c.usages });
        try g.add(c);
    }
}

/// An extendedKeyUsage extension with no KeyPurposeId, on the leaf or on the
/// intermediate. RFC 5280 §4.2.1.12 has `SIZE (1..MAX)`; Go reads the empty
/// list as no restriction.
fn genEkuEmpty(g: *Gen) !void {
    const d = g.bd.d;
    const empty_rule = "RFC 5280 §4.2.1.12: ExtKeyUsageSyntax is SEQUENCE SIZE (1..MAX), an empty extendedKeyUsage is malformed and grants no usage; Go reads it as no restriction";
    for ([_]bool{ false, true }) |on_inter| for ([_]u8{ 0, 1, 2, 4 }) |usages| {
        const ca: []const []const u8 = &.{ try extBc(d, true, null), try extKuCa(d) };
        const ch = try g.bd.chain(.{
            .inter_exts = if (on_inter) &.{ ca[0], ca[1], try extEku(d, 0) } else null,
            .leaf_exts = if (on_inter) null else &.{ try extSan(d, &.{.{ .dns = "example.com" }}), try extKuLeaf(d), try extEku(d, 0) },
        });
        var c = g.verifyCase(try g.id("eku-empty-{s}-u{d}", .{ if (on_inter) "inter" else "leaf", usages }), "eku-empty", ch);
        c.usages = usages;
        // Asking for anyExtendedKeyUsage switches the EKU check off on both sides.
        c.expect = if (usages == 4) .agree else .stricter;
        c.why = if (usages == 4) "usages {any}: no EKU check on either side" else empty_rule;
        try g.add(c);
    };
}

/// The corpus.bin record format, version 3: after `go_ok` one byte with the
/// expectation (1 = stricter, 2 = processes). Only generated rows that are
/// not `agree` are written.
fn writeLeads(io: std.Io, a: Allocator, cases: []const Case, go_ok: []const bool) !usize {
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    var n: u32 = 0;
    for (cases) |c| {
        if (c.frozen_go == null and c.expect != .agree) n += 1;
    }
    try w.writeAll("X509S2\x00\x03");
    try w.writeInt(u32, n, .little);
    for (cases, go_ok) |c, ok| {
        if (c.frozen_go != null or c.expect == .agree) continue;
        const host = if (c.mode == .verify) c.dns_name orelse "" else c.host;
        try w.writeByte(@intCast(c.id.len));
        try w.writeAll(c.id);
        try w.writeByte(@intFromBool(c.mode == .hostname));
        try w.writeInt(i64, c.time, .little);
        try w.writeByte(@intCast(host.len));
        try w.writeAll(host);
        try w.writeByte(c.usages);
        std.debug.assert(c.policies.len == 0);
        try w.writeByte(0);
        try w.writeByte(@intFromBool(ok));
        try w.writeByte(@as(u8, if (c.expect == .stricter) 1 else 2));
        try w.writeByte(@intCast(c.roots.len));
        try w.writeByte(@intCast(c.inters.len));
        for (c.roots) |x| try writeDer(w, x);
        for (c.inters) |x| try writeDer(w, x);
        try writeDer(w, c.leaf);
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = leads_path, .data = out.written() });
    return n;
}

fn writeDer(w: *std.Io.Writer, der: []const u8) !void {
    try w.writeInt(u16, @intCast(der.len), .little);
    try w.writeAll(der);
}

// ── the two sides ────────────────────────────────────────────────────────

fn ours(gpa: Allocator, a: Allocator, c: Case) !Verdict {
    switch (c.mode) {
        .hostname => {
            x509.hostname.verify(c.leaf, c.host) catch |e| return .{ .ok = false, .err = @errorName(e) };
            return .{ .ok = true, .err = "" };
        },
        .verify => {
            // Go's default `KeyUsages` is {serverAuth}.
            var usages: [3]x509.extensions.Purpose = undefined;
            var nu: usize = 0;
            if (c.usages == 0) {
                usages[0] = .server_auth;
                nu = 1;
            } else {
                inline for (.{ .{ 1, .server_auth }, .{ 2, .client_auth }, .{ 4, .any_extended_key_usage } }) |b| {
                    if (c.usages & b[0] != 0) {
                        usages[nu] = b[1];
                        nu += 1;
                    }
                }
            }
            const presented = try a.alloc([]const u8, 1 + c.inters.len);
            presented[0] = c.leaf;
            @memcpy(presented[1..], c.inters);
            _ = x509.verifyChain(gpa, presented, c.roots, .{
                .now_sec = c.time,
                .expected_host = c.dns_name,
                .usages_any_of = usages[0..nu],
                .policy = .{ .acceptable = c.policies },
            }) catch |e| return .{ .ok = false, .err = @errorName(e) };
            return .{ .ok = true, .err = "" };
        },
    }
}

fn writePem(w: *std.Io.Writer, der: []const u8) !void {
    const enc = std.base64.standard.Encoder;
    var buf: [4096]u8 = undefined;
    try w.writeAll("\"-----BEGIN CERTIFICATE-----\\n");
    var i: usize = 0;
    while (i < der.len) : (i += 48) {
        const chunk = der[i..@min(i + 48, der.len)];
        try w.writeAll(enc.encode(&buf, chunk));
        try w.writeAll("\\n");
    }
    try w.writeAll("-----END CERTIFICATE-----\\n\"");
}

fn writeJsonString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |ch| {
        if (ch == '"' or ch == '\\') try w.writeByte('\\');
        if (ch < 0x20) {
            try w.print("\\u{x:0>4}", .{ch});
        } else try w.writeByte(ch);
    }
    try w.writeByte('"');
}

/// Dotted form of a DER OID content.
fn dotted(w: *std.Io.Writer, content: []const u8) !void {
    try w.print("{d}.{d}", .{ content[0] / 40, content[0] % 40 });
    var v: u64 = 0;
    for (content[1..]) |b| {
        v = (v << 7) | (b & 0x7f);
        if (b & 0x80 == 0) {
            try w.print(".{d}", .{v});
            v = 0;
        }
    }
}

/// One line of `tools/go_oracle` input.
fn writeGoCase(w: *std.Io.Writer, c: Case) !void {
    try w.writeAll("{\"id\":");
    try writeJsonString(w, c.id);
    try w.writeAll(",\"roots\":[");
    for (c.roots, 0..) |r, i| {
        if (i != 0) try w.writeByte(',');
        try writePem(w, r);
    }
    try w.writeAll("],\"intermediates\":[");
    for (c.inters, 0..) |r, i| {
        if (i != 0) try w.writeByte(',');
        try writePem(w, r);
    }
    try w.writeAll("],\"leaf\":");
    try writePem(w, c.leaf);
    try w.print(",\"time\":{d},\"mode\":\"{t}\",\"host\":", .{ c.time, c.mode });
    try writeJsonString(w, c.host);
    try w.writeAll(",\"dns_name\":");
    if (c.dns_name) |h| try writeJsonString(w, h) else try w.writeAll("null");
    try w.writeAll(",\"key_usages\":");
    if (c.usages == 0) try w.writeAll("null") else {
        try w.writeByte('[');
        var first = true;
        inline for (.{ .{ 1, "server" }, .{ 2, "client" }, .{ 4, "any" } }) |b| {
            if (c.usages & b[0] != 0) {
                if (!first) try w.writeByte(',');
                first = false;
                try w.writeAll("\"" ++ b[1] ++ "\"");
            }
        }
        try w.writeByte(']');
    }
    try w.writeAll(",\"policies\":[");
    for (c.policies, 0..) |p, i| {
        if (i != 0) try w.writeByte(',');
        try w.writeByte('"');
        try dotted(w, p);
        try w.writeByte('"');
    }
    try w.writeAll("]}\n");
}

const GoResult = struct {
    id: []const u8,
    ok: bool,
    err_type: []const u8 = "",
    msg: []const u8 = "",
};

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(arena);
    var seed: u64 = 0x5809_2026_1026;
    var write = false;
    var i_arg: usize = 1;
    while (i_arg < args.len) : (i_arg += 1) {
        if (std.mem.eql(u8, args[i_arg], "--write")) {
            write = true;
        } else if (std.mem.eql(u8, args[i_arg], "--seed") and i_arg + 1 < args.len) {
            i_arg += 1;
            seed = std.fmt.parseInt(u64, args[i_arg], 0) catch {
                std.debug.print("interop-x509: bad --seed {s}\n", .{args[i_arg]});
                return 2;
            };
        } else {
            std.debug.print("usage: zig build interop-x509 [-- --seed N] [--write]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);

    var cases: std.ArrayList(Case) = .empty;
    try corpusCases(arena, io, &cases);
    const keys = try Keys.init();
    var bd = try Builder.init(arena, &keys);
    var prng: std.Random.DefaultPrng = .init(seed);
    var g: Gen = .{ .a = arena, .bd = &bd, .rng = prng.random(), .out = &cases };
    // The fixed families first: their certificates (serials included) must
    // not depend on the seed, `--write` freezes them.
    try genDirName(&g);
    try genEkuEmpty(&g);
    try genValidity(&g);
    try genNameConstraints(&g, 600);
    try genHostnames(&g, 600);
    try genEkuPathLen(&g, 300);

    var input: std.Io.Writer.Allocating = .init(arena);
    for (cases.items) |c| try writeGoCase(&input.writer, c);
    try dir.writeFile(io, .{ .sub_path = "cases.jsonl", .data = input.written() });

    const exe = try bench.goBuild(arena, io, "interop-x509", init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs, .out = "x509_oracle" });
    const cases_path = try std.fmt.allocPrint(arena, "{s}/cases.jsonl", .{abs});
    const judged = try std.process.run(arena, io, .{ .argv = &.{ exe, cases_path }, .stdout_limit = .limited(1 << 26) });
    if (judged.term != .exited or judged.term.exited != 0) {
        std.debug.print("interop-x509: the Go side failed:\n{s}\n", .{judged.stderr});
        return 1;
    }
    const banner = std.mem.trimEnd(u8, judged.stderr, "\n");

    var tsv: std.Io.Writer.Allocating = .init(arena);
    try tsv.writer.writeAll("id\tfamily\texpect\tgo\tours\tverdict\tgo_msg\n");
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;

    const Tally = struct { family: []const u8, n: usize = 0, leads: usize = 0, surprises: usize = 0 };
    var tallies: std.ArrayList(Tally) = .empty;
    var surprises: usize = 0;
    const go_ok = try arena.alloc(bool, cases.items.len);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, judged.stdout, "\n"), '\n');
    for (cases.items, go_ok) |c, *gok| {
        const line = lines.next() orelse {
            std.debug.print("interop-x509: the Go side stopped before {s}\n", .{c.id});
            return 1;
        };
        const gr = std.json.parseFromSliceLeaky(GoResult, arena, line, .{ .ignore_unknown_fields = true }) catch {
            std.debug.print("interop-x509: unreadable Go verdict at {s}: {s}\n", .{ c.id, line });
            return 1;
        };
        if (!std.mem.eql(u8, gr.id, c.id)) {
            std.debug.print("interop-x509: out of step at {s}: {s}\n", .{ c.id, line });
            return 1;
        }
        if (std.mem.eql(u8, gr.err_type, "oracle")) {
            std.debug.print("interop-x509: the oracle could not read {s}: {s}\n", .{ c.id, gr.msg });
            return 1;
        }
        gok.* = gr.ok;
        const u = try ours(gpa, arena, c);
        const drift = if (c.frozen_go) |f| f != gr.ok else false;
        const as_expected = !drift and switch (c.expect) {
            .agree => gr.ok == u.ok,
            .stricter => gr.ok and !u.ok,
            .processes => !gr.ok and u.ok,
        };
        const t = for (tallies.items) |*t| {
            if (std.mem.eql(u8, t.family, c.family)) break t;
        } else blk: {
            try tallies.append(arena, .{ .family = c.family });
            break :blk &tallies.items[tallies.items.len - 1];
        };
        t.n += 1;
        if (c.expect != .agree and as_expected) t.leads += 1;
        if (!as_expected) {
            t.surprises += 1;
            surprises += 1;
            try w.print("SURPRISE {s} ({s}, expect {t}): go {s}, ours {s}{s}\n    go: {s}\n", .{
                c.id,                              c.family,
                c.expect,                          if (gr.ok) "ok" else "reject",
                if (u.ok) "ok" else u.err,         if (drift) " -- Go's verdict differs from the one frozen in corpus.bin" else "",
                if (gr.ok) "accepted" else gr.msg,
            });
            if (c.why.len != 0) try w.print("    why: {s}\n", .{c.why});
        }
        try tsv.writer.print("{s}\t{s}\t{t}\t{s}\t{s}\t{s}\t{s}\n", .{
            c.id,                          c.family,                  c.expect,
            if (gr.ok) "ok" else "reject", if (u.ok) "ok" else u.err, if (as_expected) "" else "SURPRISE",
            gr.msg,
        });
    }
    try dir.writeFile(io, .{ .sub_path = "verdicts.tsv", .data = tsv.written() });

    try w.print("\n{s:<18} {s:>6} {s:>9} {s:>10}\n", .{ "family", "cases", "leads", "surprises" });
    var leads: usize = 0;
    for (tallies.items) |t| {
        leads += t.leads;
        try w.print("{s:<18} {d:>6} {d:>9} {d:>10}\n", .{ t.family, t.n, t.leads, t.surprises });
    }
    try w.print("\n{d} cases against {s} (seed 0x{x}); {d} leads as expected (stricter / processes); {d} surprise(s); verdicts in {s}/verdicts.tsv\n", .{ cases.items.len, banner, seed, leads, surprises, work_dir });
    try w.flush();
    if (write) {
        if (surprises != 0) {
            std.debug.print("interop-x509: not writing {s} over {d} surprise(s)\n", .{ leads_path, surprises });
            return 1;
        }
        std.debug.print("interop-x509: wrote {s} ({d} rows)\n", .{ leads_path, try writeLeads(io, arena, cases.items, go_ok) });
    }
    return if (surprises == 0) 0 else 1;
}
