// SPDX-License-Identifier: MIT

//! LSP and SNP authentication (`Config.auth_keys`): received LSPs, purges and
//! SNPs are verified before they touch the store; purges keep the #10 an
//! authenticated peer needs; an aged-out LSP becomes a purge signed with our
//! key. The no-key path is pinned by the rest of the suite (unchanged).

const std = @import("std");
const isis = @import("isis");
const store = @import("store.zig");
const testing = std.testing;

const Lsdb = store.Lsdb;
const Key = isis.auth.Key;

const sys_local: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_other: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };
const id_other: store.LspId = sys_other ++ [2]u8{ 0, 0 };

const key: Key = .{ .algorithm = .hmac_sha256, .id = 3, .secret = "area-secret" };
const keys = [_]Key{key};

fn cfg(k: []const Key) store.Config {
    return .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 8, .zero_age_lifetime = 60, .auth_keys = k };
}

/// An LSP from `sys_other`: #10 for `k` (if any) first, then a hostname,
/// checksum stamped, then signed (which re-stamps).
fn lsp(buf: []u8, k: ?Key, seq: u32, life: u16) ![]u8 {
    var b = try isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = id_other,
        .sequence_number = seq,
        .flags = isis.pdu.LspFlags.fromByte(0x03),
    });
    if (k) |kk| try isis.auth.addPlaceholder(&b.tlvs, kk);
    try isis.tlvs.addHostname(&b.tlvs, "peer");
    const n = b.finishStamped().len;
    if (k) |kk| try isis.auth.sign(buf[0..n], kk);
    return buf[0..n];
}

/// A purge of `id_other` carrying #10 for `k` plus `extra` raw TLVs.
fn purge(buf: []u8, k: ?Key, seq: u32, extra: []const isis.tlv.RawTlv) ![]u8 {
    var b = try isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = 0,
        .lsp_id = id_other,
        .sequence_number = seq,
        .checksum = 0x4242,
        .flags = isis.pdu.LspFlags.fromByte(0x03),
    });
    if (k) |kk| try isis.auth.addPlaceholder(&b.tlvs, kk);
    for (extra) |t| try b.tlvs.addTlv(t.code, t.value);
    const n = b.finish().len;
    if (k) |kk| try isis.auth.sign(buf[0..n], kk);
    return buf[0..n];
}

test "lsdb auth: a signed LSP is stored, every algorithm" {
    const algs = [_]isis.auth.Algorithm{ .cleartext, .hmac_md5, .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 };
    for (algs) |alg| {
        const k: Key = .{ .algorithm = alg, .id = 1, .secret = "s" };
        var db = Lsdb.init(testing.allocator, cfg(&.{k}));
        defer db.deinit();
        var buf: [256]u8 = undefined;
        const r = try db.insert(try lsp(&buf, k, 1, 1000), 1, 0);
        try testing.expect(r.stored);
    }
}

test "lsdb auth: unsigned, wrong key, wrong Key ID, tampered or malformed LSPs are refused, store unchanged" {
    var db = Lsdb.init(testing.allocator, cfg(&keys));
    defer db.deinit();
    var buf: [256]u8 = undefined;
    try testing.expectError(error.AuthMissing, db.insert(try lsp(&buf, null, 1, 1000), 1, 0));
    var wrong = key;
    wrong.secret = "area-secreT";
    try testing.expectError(error.AuthFailed, db.insert(try lsp(&buf, wrong, 1, 1000), 1, 0));
    var other_id = key;
    other_id.id = 4;
    try testing.expectError(error.AuthFailed, db.insert(try lsp(&buf, other_id, 1, 1000), 1, 0));
    // Content changed after signing, checksum re-stamped so only #10 can tell.
    const w = try lsp(&buf, key, 1, 1000);
    w[w.len - 1] ^= 0x20;
    _ = try isis.pdu.stampLspChecksum(w);
    try testing.expectError(error.AuthFailed, db.insert(w, 1, 0));
    // A #10 of the HMAC-MD5 type with a short value.
    var mb = try isis.pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 1000, .lsp_id = id_other, .sequence_number = 1, .flags = isis.pdu.LspFlags.fromByte(3) });
    var v: [10]u8 = @splat(0);
    v[0] = isis.auth.auth_type.hmac_md5;
    try mb.tlvs.addTlv(isis.auth.tlv_code, &v);
    try testing.expectError(error.AuthFailed, db.insert(mb.finishStamped(), 1, 0));
    try testing.expectEqual(@as(usize, 0), db.count());
}

test "lsdb auth: no keys accepts signed and unsigned alike; keys do not gate local originations" {
    var plain = Lsdb.init(testing.allocator, cfg(&.{}));
    defer plain.deinit();
    var buf: [256]u8 = undefined;
    _ = try plain.insert(try lsp(&buf, key, 1, 1000), 1, 0);
    _ = try plain.insert(try lsp(&buf, null, 2, 1000), 1, 0);
    try testing.expectEqual(@as(u32, 2), plain.get(id_other, 0).?.sequence_number);

    var keyed = Lsdb.init(testing.allocator, cfg(&keys));
    defer keyed.deinit();
    try testing.expect((try keyed.insert(try lsp(&buf, null, 1, 1000), null, 0)).stored);
}

test "lsdb auth: an LSP aged in flight (Remaining Lifetime lowered) still verifies" {
    var db = Lsdb.init(testing.allocator, cfg(&keys));
    defer db.deinit();
    var buf: [256]u8 = undefined;
    const w = try lsp(&buf, key, 1, 1000);
    std.mem.writeInt(u16, w[10..12], 700, .big);
    try testing.expect((try db.insert(w, 1, 0)).stored);
}

test "lsdb auth: purges — signed with allowed TLVs kept whole, unsigned or with other TLVs refused" {
    var db = Lsdb.init(testing.allocator, cfg(&keys));
    defer db.deinit();
    var buf: [256]u8 = undefined;
    _ = try db.insert(try lsp(&buf, key, 1, 1000), 1, 0);

    var pbuf: [256]u8 = undefined;
    // RFC 5304 §2: no unauthenticated purge.
    try testing.expectError(error.AuthMissing, db.insert(try purge(&pbuf, null, 2, &.{}), 1, 1));
    // RFC 5304 §2 / RFC 6233: only #10, #13, #137.
    const zeros12: [12]u8 = @splat(0);
    const is_reach = [_]isis.tlv.RawTlv{.{ .code = 2, .value = &zeros12 }};
    try testing.expectError(error.InvalidPurge, db.insert(try purge(&pbuf, key, 2, &is_reach), 1, 1));
    try testing.expect(!db.get(id_other, 1).?.is_purge);

    const allowed = [_]isis.tlv.RawTlv{
        .{ .code = 13, .value = &.{ 1, 0, 0, 0, 0, 0, 0xB } },
        .{ .code = 137, .value = "peer" },
    };
    const p = try purge(&pbuf, key, 2, &allowed);
    try testing.expect((try db.insert(p, 1, 1)).stored);
    const v = db.get(id_other, 1).?;
    try testing.expect(v.is_purge);
    // Kept verbatim, so it still verifies and can be flooded to keyed peers.
    try testing.expectEqualSlices(u8, p, v.bytes);
    try testing.expectEqual(@as(usize, 0), try isis.auth.verify(v.bytes, &keys));
    var peer = Lsdb.init(testing.allocator, cfg(&keys));
    defer peer.deinit();
    _ = try peer.insert(try lsp(&buf, key, 1, 1000), 1, 0);
    try testing.expect((try peer.insert(v.bytes, 0, 2)).stored);
}

test "lsdb auth: a purge whose TLV stream breaks after #10 is refused" {
    var db = Lsdb.init(testing.allocator, cfg(&keys));
    defer db.deinit();
    var buf: [256]u8 = undefined;
    _ = try db.insert(try lsp(&buf, key, 1, 1000), 1, 0);
    var pbuf: [256]u8 = undefined;
    const allowed = [_]isis.tlv.RawTlv{.{ .code = 137, .value = "peer" }};
    const p = try purge(&pbuf, key, 2, &allowed);
    // Grow PDU Length by one octet of a dangling TLV header, then re-sign.
    var big: [256]u8 = undefined;
    @memcpy(big[0..p.len], p);
    big[p.len] = 137;
    std.mem.writeInt(u16, big[8..10], @intCast(p.len + 1), .big);
    try isis.auth.sign(big[0 .. p.len + 1], key);
    try testing.expectError(error.InvalidPurge, db.insert(big[0 .. p.len + 1], 1, 1));
}

test "lsdb auth: an LSP aged out here becomes a purge signed with auth_keys[0], checksum kept" {
    const ks = [_]Key{ key, .{ .algorithm = .hmac_md5, .secret = "old" } };
    var db = Lsdb.init(testing.allocator, cfg(&ks));
    defer db.deinit();
    var buf: [256]u8 = undefined;
    const w = try lsp(&buf, key, 7, 100);
    const csum = (try isis.Lsp.decode(w)).checksum;
    _ = try db.insert(w, 1, 0);
    try testing.expectEqual(@as(usize, 1), db.tick(100).entered_purge);
    const v = db.get(id_other, 100).?;
    try testing.expect(v.is_purge);
    const d = try isis.Lsp.decode(v.bytes);
    try testing.expectEqual(@as(u16, 0), d.remaining_lifetime);
    try testing.expectEqual(csum, d.checksum);
    try testing.expectEqual(@as(u32, 7), d.sequence_number);
    // Exactly one TLV, our #10, and it verifies with the first key.
    try testing.expectEqual(@as(usize, 1), try isis.tlv.count(d.tlv_bytes));
    try testing.expectEqual(@as(usize, 0), try isis.auth.verify(v.bytes, &.{key}));
    try testing.expectError(error.KeyNotFound, isis.auth.verify(v.bytes, &.{ks[1]}));
    // And a keyed peer holding the live LSP accepts it as the purge.
    var peer = Lsdb.init(testing.allocator, cfg(&keys));
    defer peer.deinit();
    _ = try peer.insert(try lsp(&buf, key, 7, 1000), 1, 0);
    try testing.expect((try peer.insert(v.bytes, 0, 1)).stored);
    try testing.expect(peer.get(id_other, 1).?.is_purge);
}

test "lsdb auth: aging falls back to the header alone when #10 cannot be built" {
    const pw: [255]u8 = @splat('p'); // too long for a cleartext TLV value
    const k: Key = .{ .algorithm = .cleartext, .secret = &pw };
    var db = Lsdb.init(testing.allocator, cfg(&.{k}));
    defer db.deinit();
    var buf: [256]u8 = undefined;
    _ = try db.insert(try lsp(&buf, null, 1, 100), null, 0); // local injection: not verified
    _ = db.tick(100);
    try testing.expectEqual(@as(usize, isis.pdu.lsp_fixed_len), db.get(id_other, 100).?.bytes.len);
}

test "lsdb auth: aging falls back to the header alone when the allocation fails" {
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    var db = Lsdb.init(fa.allocator(), cfg(&keys));
    defer db.deinit();
    var buf: [256]u8 = undefined;
    // A short LSP: the signed purge (27 + 37) is larger, so realloc must grow.
    var b = try isis.pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 100, .lsp_id = id_other, .sequence_number = 1, .flags = isis.pdu.LspFlags.fromByte(3) });
    try isis.auth.addPlaceholder(&b.tlvs, .{ .algorithm = .cleartext, .secret = "x" });
    _ = try db.insert(b.finishStamped(), null, 0);
    fa.fail_index = fa.alloc_index;
    fa.resize_fail_index = fa.resize_index;
    _ = db.tick(100);
    const v = db.get(id_other, 100).?;
    try testing.expect(v.is_purge);
    try testing.expectEqual(@as(usize, isis.pdu.lsp_fixed_len), (try isis.Lsp.decode(v.bytes)).pdu_length);
}

fn csnp(buf: []u8, k: ?Key) ![]u8 {
    var b = try isis.pdu.CsnpBuilder.init(buf, .{ .source_id = sys_other ++ [1]u8{0}, .start_lsp_id = @splat(0), .end_lsp_id = @splat(0xff) });
    if (k) |kk| try isis.auth.addPlaceholder(&b.tlvs, kk);
    try isis.tlvs.addLspEntries(&b.tlvs, &.{.{ .remaining_lifetime = 900, .lsp_id = id_other, .sequence_number = 9, .checksum = 0x1234 }});
    const n = b.finish().len;
    if (k) |kk| try isis.auth.sign(buf[0..n], kk);
    return buf[0..n];
}

fn psnp(buf: []u8, k: ?Key) ![]u8 {
    var b = try isis.pdu.PsnpBuilder.init(buf, .{ .source_id = sys_other ++ [1]u8{0} });
    if (k) |kk| try isis.auth.addPlaceholder(&b.tlvs, kk);
    try isis.tlvs.addLspEntries(&b.tlvs, &.{.{ .remaining_lifetime = 900, .lsp_id = id_other, .sequence_number = 9, .checksum = 0x1234 }});
    const n = b.finish().len;
    if (k) |kk| try isis.auth.sign(buf[0..n], kk);
    return buf[0..n];
}

test "lsdb auth: CSNP and PSNP are verified before they reconcile" {
    var buf: [256]u8 = undefined;
    var wrong = key;
    wrong.secret = "nope";
    inline for (.{ csnp, psnp }, .{ "csnp", "psnp" }) |build, kind| {
        var db = Lsdb.init(testing.allocator, cfg(&keys));
        defer db.deinit();
        const reconcile = if (comptime std.mem.eql(u8, kind, "csnp")) Lsdb.reconcileCsnpBytes else Lsdb.reconcilePsnpBytes;
        try testing.expectError(error.AuthMissing, reconcile(&db, try build(&buf, null), 0, 0));
        try testing.expectError(error.AuthFailed, reconcile(&db, try build(&buf, wrong), 0, 0));
        try testing.expectEqual(@as(usize, 0), db.count()); // no request placeholder
        try reconcile(&db, try build(&buf, key), 0, 0);
        try testing.expectEqual(@as(usize, 1), db.count()); // the advertised LSP is requested
        // Unkeyed: unsigned SNPs reconcile as before.
        var plain = Lsdb.init(testing.allocator, cfg(&.{}));
        defer plain.deinit();
        try reconcile(&plain, try build(&buf, null), 0, 0);
        try testing.expectEqual(@as(usize, 1), plain.count());
        // A wrong PDU type is a decode error either way.
        try testing.expectError(error.WrongPduType, reconcile(&plain, try lsp(&buf, null, 1, 10), 0, 0));
    }
}

test "lsdb auth: auth_snp=false accepts unsigned and signed SNPs, default still refuses, LSPs unaffected" {
    var buf: [256]u8 = undefined;
    var c = cfg(&keys);
    c.auth_snp = false;
    inline for (.{ csnp, psnp }, .{ "csnp", "psnp" }) |build, kind| {
        const reconcile = if (comptime std.mem.eql(u8, kind, "csnp")) Lsdb.reconcileCsnpBytes else Lsdb.reconcilePsnpBytes;
        var off = Lsdb.init(testing.allocator, c);
        defer off.deinit();
        try reconcile(&off, try build(&buf, null), 0, 0);
        try testing.expectEqual(@as(usize, 1), off.count());
        var wrong = key;
        wrong.secret = "nope";
        var off2 = Lsdb.init(testing.allocator, c);
        defer off2.deinit();
        try reconcile(&off2, try build(&buf, wrong), 0, 0); // not verified at all
        try testing.expectEqual(@as(usize, 1), off2.count());
        // The default (true) with the same keys still refuses.
        var on = Lsdb.init(testing.allocator, cfg(&keys));
        defer on.deinit();
        try testing.expectError(error.AuthMissing, reconcile(&on, try build(&buf, null), 0, 0));
        try testing.expectEqual(@as(usize, 0), on.count());
    }
    // LSPs are still verified with auth_snp=false.
    var db = Lsdb.init(testing.allocator, c);
    defer db.deinit();
    try testing.expectError(error.AuthMissing, db.insert(try lsp(&buf, null, 1, 10), 1, 0));
}

// -- delta mutation 2026-11-18 ------------------------------------------------

test "lsdb auth: the purge TLV rule applies to purges only, a live LSP may carry any TLV" {
    var db = Lsdb.init(testing.allocator, cfg(&keys));
    defer db.deinit();
    var buf: [256]u8 = undefined;
    var b = try isis.pdu.LspBuilder.init(&buf, .{ .remaining_lifetime = 1000, .lsp_id = id_other, .sequence_number = 1, .flags = isis.pdu.LspFlags.fromByte(3) });
    try isis.auth.addPlaceholder(&b.tlvs, key);
    try isis.tlvs.addAreaAddresses(&b.tlvs, &.{&[_]u8{ 0x49, 0, 1 }});
    try isis.tlvs.addProtocolsSupported(&b.tlvs, &.{isis.tlvs.nlpid_ipv4});
    const n = b.finishStamped().len;
    try isis.auth.sign(buf[0..n], key);
    try testing.expect((try db.insert(buf[0..n], 1, 0)).stored);
}
