// SPDX-License-Identifier: MIT

//! Sender-side authentication (`Config.auth_keys`, RFC 5304 / RFC 5310): CSNPs
//! and PSNPs are signed with `auth_keys[0]`, LSPs are forwarded as stored, and
//! every shape is checked against the real receiver (`isis-lsdb`) and against
//! `isis.auth.verify`. The no-key path is pinned by the rest of the suite
//! (the goldens are unchanged).

const std = @import("std");
const isis = @import("isis");
const lsdb_mod = @import("isis-lsdb");
const scheduler = @import("scheduler.zig");
const snp = @import("snp.zig");
const testing = std.testing;

const Lsdb = lsdb_mod.Lsdb;
const Scheduler = scheduler.Scheduler;
const Effect = scheduler.Effect;
const Key = isis.auth.Key;

const sys_a: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };
const id_b: [8]u8 = sys_b ++ [2]u8{ 0, 0 };

const key: Key = .{ .algorithm = .hmac_sha256, .id = 7, .secret = "link-secret" };
const other_key: Key = .{ .algorithm = .hmac_sha256, .id = 7, .secret = "another-secret" };
const keys = [_]Key{key};

fn up0() scheduler.InterfaceSet {
    var s = scheduler.InterfaceSet.empty;
    s.set(0);
    return s;
}

/// An LSP of `sys_b`: #10 for `k` first, a hostname, stamped, signed.
fn lspOf(buf: []u8, k: ?Key, seq: u32) ![]u8 {
    var b = try isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = id_b,
        .sequence_number = seq,
        .flags = isis.pdu.LspFlags.fromByte(0x03),
    });
    if (k) |kk| try isis.auth.addPlaceholder(&b.tlvs, kk);
    try isis.tlvs.addHostname(&b.tlvs, "peer");
    const n = b.finishStamped().len;
    if (k) |kk| try isis.auth.sign(buf[0..n], kk);
    return buf[0..n];
}

fn keyedDb(k: []const Key, auth_snp: bool) Lsdb {
    return Lsdb.init(testing.allocator, .{
        .local_system_id = sys_a,
        .interface_count = 2,
        .capacity = 16,
        .auth_keys = k,
        .auth_snp = auth_snp,
    });
}

/// `db` holds `sys_b`'s keyed LSP as received on circuit 1, so circuit 0 owes
/// it (SRM) and circuit 1 an ack (SSN).
fn withLsp(db: *Lsdb) !void {
    var buf: [256]u8 = undefined;
    _ = try db.insert(try lspOf(&buf, key, 1), 1, 0);
}

fn firstOf(effects: []const Effect, kind: scheduler.PduKind) ?Effect {
    for (effects) |e| if (e.kind == kind) return e;
    return null;
}

fn hasAuth(bytes: []const u8) !bool {
    return (try isis.auth.find(bytes)) != null;
}

test "keyed scheduler: CSNP and PSNP carry a #10 that verifies; the LSP is forwarded untouched" {
    var db = keyedDb(&keys, true);
    defer db.deinit();
    try withLsp(&db);
    var stored: [256]u8 = undefined;
    var lbuf: [256]u8 = undefined;
    const lsp = try lspOf(&lbuf, key, 1);
    @memcpy(stored[0..lsp.len], lsp);

    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_a, .auth_keys = &keys });
    defer sched.deinit();
    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    // Circuit 1 is Up: it owes the ack (PSNP) and the first CSNP; circuit 0 the LSP.
    var up = up0();
    up.set(1);
    const r = sched.poll(0, up, &db, &out, &scratch);

    const psnp = firstOf(r.effects, .psnp).?;
    try testing.expectEqual(@as(usize, 0), try isis.auth.verify(psnp.bytes, &keys));
    const csnp = firstOf(r.effects, .csnp).?;
    try testing.expectEqual(@as(usize, 0), try isis.auth.verify(csnp.bytes, &keys));
    // The #10 is the first TLV (holo / FRR placement) and names our Key ID.
    const cs = try isis.Csnp.decode(csnp.bytes);
    try testing.expectEqual(isis.auth.tlv_code, cs.tlv_bytes[0]);
    // The LSP leaves exactly as the originator signed it: not re-signed.
    const lsp_eff = firstOf(r.effects, .lsp).?;
    try testing.expectEqualSlices(u8, stored[0..lsp.len], lsp_eff.bytes);
    try testing.expectEqual(@as(usize, 0), try isis.auth.verify(lsp_eff.bytes, &keys));

    // The real receiver accepts them; one with another key refuses both.
    var rx = keyedDb(&keys, true);
    defer rx.deinit();
    try rx.reconcileCsnpBytes(csnp.bytes, 0, 0);
    try rx.reconcilePsnpBytes(psnp.bytes, 0, 0);
    const wrong = [_]Key{other_key};
    var rx_bad = keyedDb(&wrong, true);
    defer rx_bad.deinit();
    try testing.expectError(error.AuthFailed, rx_bad.reconcileCsnpBytes(csnp.bytes, 0, 0));
    try testing.expectError(error.AuthFailed, rx_bad.reconcilePsnpBytes(psnp.bytes, 0, 0));
}

test "keyed scheduler signs every chunk of a multi-PDU CSNP and PSNP series" {
    var db = keyedDb(&keys, true);
    defer db.deinit();
    for (0..5) |n| {
        var buf: [256]u8 = undefined;
        var b = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = sys_b ++ [2]u8{ 0, @intCast(n) },
            .sequence_number = 1,
            .flags = isis.pdu.LspFlags.fromByte(0x03),
        });
        try isis.auth.addPlaceholder(&b.tlvs, key);
        const len = b.finishStamped().len;
        try isis.auth.sign(buf[0..len], key);
        _ = try db.insert(buf[0..len], 1, 0);
    }
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_a, .auth_keys = &keys, .lsp_entries_per_pdu = 2 });
    defer sched.deinit();
    var out: [32]Effect = undefined;
    var scratch: [4096]u8 = undefined;
    var up = up0();
    up.set(1);
    const r = sched.poll(0, up, &db, &out, &scratch);
    var csnps: usize = 0;
    var psnps: usize = 0;
    for (r.effects) |e| switch (e.kind) {
        .csnp, .psnp => {
            try testing.expectEqual(@as(usize, 0), try isis.auth.verify(e.bytes, &keys));
            if (e.kind == .csnp) csnps += 1 else psnps += 1;
        },
        .lsp => {},
    };
    try testing.expect(csnps >= 1);
    try testing.expectEqual(@as(usize, 3), psnps); // 5 acks at 2 per PDU
}

test "auth_snp = false: unsigned SNPs, a receiver with auth_snp = false takes them, a default one refuses" {
    var db = keyedDb(&keys, false);
    defer db.deinit();
    try withLsp(&db);
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_a, .auth_keys = &keys, .auth_snp = false });
    defer sched.deinit();
    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    var up = up0();
    up.set(1);
    const r = sched.poll(0, up, &db, &out, &scratch);
    const psnp = firstOf(r.effects, .psnp).?;
    const csnp = firstOf(r.effects, .csnp).?;
    try testing.expect(!try hasAuth(psnp.bytes));
    try testing.expect(!try hasAuth(csnp.bytes));
    // LSPs are still keyed (auth_snp only concerns SNPs) and forwarded as stored.
    try testing.expect(try hasAuth(firstOf(r.effects, .lsp).?.bytes));

    var rx_off = keyedDb(&keys, false);
    defer rx_off.deinit();
    try rx_off.reconcileCsnpBytes(csnp.bytes, 0, 0);
    try rx_off.reconcilePsnpBytes(psnp.bytes, 0, 0);
    var rx_on = keyedDb(&keys, true);
    defer rx_on.deinit();
    try testing.expectError(error.AuthMissing, rx_on.reconcileCsnpBytes(csnp.bytes, 0, 0));
    try testing.expectError(error.AuthMissing, rx_on.reconcilePsnpBytes(psnp.bytes, 0, 0));
}

test "no keys: SNPs carry no #10 and buildXxxSigned(null) is buildXxx" {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_a, .interface_count = 2, .capacity = 16 });
    defer db.deinit();
    var buf: [256]u8 = undefined;
    _ = try db.insert(try lspOf(&buf, null, 1), 1, 0);
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_a });
    defer sched.deinit();
    var out: [16]Effect = undefined;
    var scratch: [1024]u8 = undefined;
    var up = up0();
    up.set(1);
    const r = sched.poll(0, up, &db, &out, &scratch);
    try testing.expect(!try hasAuth(firstOf(r.effects, .csnp).?.bytes));
    try testing.expect(!try hasAuth(firstOf(r.effects, .psnp).?.bytes));

    const e = [_]snp.LspEntry{.{ .remaining_lifetime = 9, .lsp_id = id_b, .sequence_number = 2, .checksum = 3 }};
    var x: [128]u8 = undefined;
    var y: [128]u8 = undefined;
    const sid: [7]u8 = @splat(1);
    try testing.expectEqualSlices(u8, try snp.buildCsnp(&x, sid, true, snp.min_lsp_id, snp.max_lsp_id, &e), try snp.buildCsnpSigned(&y, sid, true, snp.min_lsp_id, snp.max_lsp_id, &e, null));
    try testing.expectEqualSlices(u8, try snp.buildPsnp(&x, sid, true, &e), try snp.buildPsnpSigned(&y, sid, true, &e, null));
}

test "snp builders: every algorithm signs a PDU its own key verifies and a neighbour's key does not" {
    const algs = [_]isis.auth.Algorithm{ .cleartext, .hmac_md5, .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 };
    const e = [_]snp.LspEntry{.{ .remaining_lifetime = 9, .lsp_id = id_b, .sequence_number = 2, .checksum = 3 }};
    const sid: [7]u8 = @splat(1);
    for (algs) |alg| {
        const k: Key = .{ .algorithm = alg, .id = 5, .secret = "s3cret" };
        const bad: Key = .{ .algorithm = alg, .id = 5, .secret = "s4cret" };
        var buf: [256]u8 = undefined;
        const cw = try snp.buildCsnpSigned(&buf, sid, false, snp.min_lsp_id, snp.max_lsp_id, &e, k);
        try testing.expectEqual(@as(usize, 0), try isis.auth.verify(cw, &.{k}));
        try testing.expectError(error.AuthFailed, isis.auth.verify(cw, &.{bad}));
        const pw = try snp.buildPsnpSigned(&buf, sid, false, &e, k);
        try testing.expectEqual(@as(usize, 0), try isis.auth.verify(pw, &.{k}));
        try testing.expectError(error.AuthFailed, isis.auth.verify(pw, &.{bad}));
        // The entries survive the #10 in front of them.
        const ps = try isis.Psnp.decode(pw);
        var it = isis.tlv.TlvIterator.init(ps.tlv_bytes);
        _ = (try it.next()).?; // #10
        const t9 = (try it.next()).?;
        try testing.expectEqual(isis.tlvs.code.lsp_entries, t9.code);
    }
}

test "snp builders: a key whose #10 cannot be built or does not fit is a typed error" {
    const e = [_]snp.LspEntry{.{ .remaining_lifetime = 9, .lsp_id = id_b, .sequence_number = 2, .checksum = 3 }};
    const sid: [7]u8 = @splat(1);
    var buf: [512]u8 = undefined;
    const long: [260]u8 = @splat('x');
    const k: Key = .{ .algorithm = .cleartext, .secret = &long };
    try testing.expectError(error.ValueTooLong, snp.buildPsnpSigned(&buf, sid, false, &e, k));
    try testing.expectError(error.ValueTooLong, snp.buildCsnpSigned(&buf, sid, false, snp.min_lsp_id, snp.max_lsp_id, &e, k));
    // A scratch that fits the unsigned PDU but not the signed one.
    var tight: [128]u8 = undefined;
    const unsigned_len = (try snp.buildPsnp(&tight, sid, false, &e)).len;
    try testing.expectError(error.BufferTooSmall, snp.buildPsnpSigned(tight[0..unsigned_len], sid, false, &e, key));
}

test "with several keys the first signs (rollover): a receiver holding only that key accepts" {
    const old: Key = .{ .algorithm = .hmac_sha256, .id = 1, .secret = "old-secret" };
    const both = [_]Key{ key, old };
    var db = keyedDb(&both, true);
    defer db.deinit();
    var sched = Scheduler.init(testing.allocator, .{ .local_system_id = sys_a, .auth_keys = &both });
    defer sched.deinit();
    var out: [4]Effect = undefined;
    var scratch: [512]u8 = undefined;
    const r = sched.poll(0, up0(), &db, &out, &scratch);
    const csnp = firstOf(r.effects, .csnp).?;
    try testing.expectEqual(@as(usize, 0), try isis.auth.verify(csnp.bytes, &.{key}));
    try testing.expectError(error.KeyNotFound, isis.auth.verify(csnp.bytes, &.{old}));
}
