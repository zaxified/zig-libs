// SPDX-License-Identifier: MIT

//! Dead-stack probe for every secret-touching entry point (`testkit.stackprobe`):
//! residue below each burn, and the root seeds / MAC secret / share bytes as
//! needles in any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime
//! skip, so the body is type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 128 * 1024 });

const Single = root.Pir(8, 4);
const Multi = Single.Multi(3);
const V = root.Verified(8, 4, 8);

var s: [4][16]u8 = undefined;
var ms0: [3][16]u8 = undefined;
var ms1: [3][16]u8 = undefined;
var mac_rand: [V.tag_word_len]u8 = undefined;
var shares: [2]Single.Share = undefined;
var mshares: [2]Multi.Share = undefined;
var vq: V.Query = undefined;
var parsed: Single.Share = undefined;
var mparsed: Multi.Share = undefined;
var vparsed: V.Share = undefined;
var wire: [Single.share_len]u8 = undefined;
var mwire: [Multi.share_len]u8 = undefined;
var vwire: [V.share_len]u8 = undefined;
var db_bytes: [100 * 6]u8 = undefined;
var words: [2]Single.Word = undefined;
var mwords: [3 * 2]Multi.Word = undefined;
var vwords: [2]V.Word = undefined;
var vtags: [3]V.TagWord = undefined;
var rec: [6]u8 = undefined;

fn seed(out: []u8, label: []const u8) void {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &h, .{});
    @memcpy(out, h[0..out.len]);
}

fn setup() void {
    const labels = [_][]const u8{ "pir probe s0", "pir probe s1", "pir probe s2", "pir probe s3" };
    for (&s, labels) |*d, l| seed(d, l);
    for (0..3) |j| {
        var l: [16]u8 = undefined;
        _ = std.fmt.bufPrint(&l, "pir probe m0 {d}", .{j}) catch unreachable;
        seed(&ms0[j], &l);
        _ = std.fmt.bufPrint(&l, "pir probe m1 {d}", .{j}) catch unreachable;
        seed(&ms1[j], &l);
    }
    seed(&mac_rand, "pir probe mac");
    for (&db_bytes, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
}

fn shareSecrets(sh: anytype) [4][]const u8 {
    return .{ &sh[0].seed, &sh[1].seed, std.mem.sliceAsBytes(&sh[0].cw), std.mem.sliceAsBytes(&sh[1].cw) };
}

test "STACKPROBE: no seed, MAC secret or share residue after any entry point" {
    try sp.skipUnlessOptimized();
    setup();
    const db = try root.Database.init(&db_bytes, 6);

    // ── client: query construction ──
    _ = try P.run("Pir.query", Single.query, .{ 77, &s[0], &s[1], &shares }, &(shareSecrets(&shares) ++ .{ &s[0], &s[1] }), .{});
    _ = try P.run("Pir.queryKeyword", Single.queryKeyword, .{ "alpha", &s[0], &s[1], &shares }, &(shareSecrets(&shares) ++ .{ &s[0], &s[1] }), .{});
    _ = try P.run("Multi.query", Multi.query, .{ .{ 3, 9, 77 }, &ms0, &ms1, &mshares }, &[_][]const u8{ &ms0[0], &ms0[1], &ms0[2], &ms1[0], &ms1[1], &ms1[2], &mshares[0].keys[0].seed, &mshares[1].keys[1].seed }, .{});
    _ = try P.run("Verified.query", V.query, .{ 77, &mac_rand, &s[0], &s[1], &s[2], &s[3], &vq }, &[_][]const u8{ &mac_rand, &s[0], &s[1], &s[2], &s[3], std.mem.asBytes(&vq.secret.m), &vq.shares[0].value.seed, &vq.shares[1].tag.seed }, .{});
    _ = try P.run("Verified.queryKeyword", V.queryKeyword, .{ "alpha", &mac_rand, &s[0], &s[1], &s[2], &s[3], &vq }, &[_][]const u8{ &mac_rand, &s[0], &s[1], &s[2], &s[3], std.mem.asBytes(&vq.secret.m), &vq.shares[0].value.seed, &vq.shares[1].tag.seed }, .{});

    // ── share codec (the wire form of the secret-bearing query) ──
    try Single.query(77, &s[0], &s[1], &shares);
    Single.shareToBytes(&shares[0], &wire);
    _ = try P.run("Pir.shareToBytes", Single.shareToBytes, .{ &shares[0], &wire }, &[_][]const u8{ &wire, &shares[0].seed }, .{});
    _ = try P.run("Pir.shareFromBytes", Single.shareFromBytes, .{ &parsed, &wire }, &[_][]const u8{ &wire, &parsed.seed }, .{});
    try Multi.query(.{ 3, 9, 77 }, &ms0, &ms1, &mshares);
    Multi.shareToBytes(&mshares[0], &mwire);
    _ = try P.run("Multi.shareToBytes", Multi.shareToBytes, .{ &mshares[0], &mwire }, &[_][]const u8{&mwire}, .{});
    _ = try P.run("Multi.shareFromBytes", Multi.shareFromBytes, .{ &mparsed, &mwire }, &[_][]const u8{ &mwire, &mparsed.keys[0].seed }, .{});
    try V.query(77, &mac_rand, &s[0], &s[1], &s[2], &s[3], &vq);
    V.shareToBytes(&vq.shares[0], &vwire);
    _ = try P.run("Verified.shareToBytes", V.shareToBytes, .{ &vq.shares[0], &vwire }, &[_][]const u8{&vwire}, .{});
    _ = try P.run("Verified.shareFromBytes", V.shareFromBytes, .{ &vparsed, &vwire }, &[_][]const u8{ &vwire, &vparsed.value.seed, &vparsed.tag.seed }, .{});

    // ── server: answers over a key share ──
    _ = try P.run("Pir.answer", Single.answer, .{ 0, &shares[0], db, &words }, &[_][]const u8{ &wire, &shares[0].seed }, .{});
    _ = try P.run("Multi.answer", Multi.answer, .{ 0, &mshares[0], db, &mwords }, &[_][]const u8{&mwire}, .{});
    _ = try P.run("Verified.answer", V.answer, .{ 0, &vq.shares[0], db, &vwords, &vtags }, &[_][]const u8{&vwire}, .{});

    // ── client: verify + reconstruct with the MAC secret ──
    var v0: [2]V.Word = undefined;
    var v1: [2]V.Word = undefined;
    var t0: [3]V.TagWord = undefined;
    var t1: [3]V.TagWord = undefined;
    try V.answer(0, &vq.shares[0], db, &v0, &t0);
    try V.answer(1, &vq.shares[1], db, &v1, &t1);
    _ = try P.run("Verified.reconstruct", V.reconstruct, .{ &vq.secret, &v0, &v1, &t0, &t1, &rec }, &[_][]const u8{ std.mem.asBytes(&vq.secret.m), &rec }, .{});
}
