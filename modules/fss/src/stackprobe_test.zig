// SPDX-License-Identifier: MIT

//! Dead-stack probe for every secret-touching entry point (`testkit.stackprobe`):
//! residue below each burn, and the root seeds / serialized key bytes as needles
//! in any frame. ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so
//! the body is type-checked in every mode).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 128 * 1024 });

const D = root.Dpf(10, 4);
const DS = root.DpfWith(root.prg.Sha256Prg, 10, 4);
const M = root.Mpf(8, 4, 3);

var s0: [16]u8 = undefined;
var s1: [16]u8 = undefined;
var ms0: [3][16]u8 = undefined;
var ms1: [3][16]u8 = undefined;
var key0: D.Key = undefined;
var key1: D.Key = undefined;
var skey: DS.Key = undefined;
var mkey0: M.Key = undefined;
var mkey1: M.Key = undefined;
var key_bytes: [D.Key.serialized_len]u8 = undefined;
var key_bytes1: [D.Key.serialized_len]u8 = undefined;
var mkey_bytes: [M.Key.serialized_len]u8 = undefined;
var tagged: [D.Key.tagged_len]u8 = undefined;
var cw_bytes: [D.Key.cw_serialized_len]u8 = undefined;
var decoded: D.Key = undefined;
var mdecoded: M.Key = undefined;
var tagged_decoded: D.Key = undefined;
var gen_out: [2]D.Key = undefined;
var sgen_out: [2]DS.Key = undefined;
var mgen_out: [2]M.Key = undefined;
var evals: [D.domain_size]D.Elem = undefined;
var sink_count: usize = 0;
var mshares: [M.domain_size]M.Elem = undefined;

fn seed(out: []u8, label: []const u8) void {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &h, .{});
    @memcpy(out, h[0..out.len]);
}

fn setup() void {
    seed(&s0, "fss probe seed 0");
    seed(&s1, "fss probe seed 1");
    for (0..3) |j| {
        var l: [16]u8 = undefined;
        _ = std.fmt.bufPrint(&l, "fss probe m0 {d}", .{j}) catch unreachable;
        seed(&ms0[j], &l);
        _ = std.fmt.bufPrint(&l, "fss probe m1 {d}", .{j}) catch unreachable;
        seed(&ms1[j], &l);
    }
    var k: [2]D.Key = undefined;
    D.genWithSeeds(333, 0x01020304, &s0, &s1, &k);
    key0 = k[0];
    key1 = k[1];
    var sk: [2]DS.Key = undefined;
    DS.genWithSeeds(333, 0x01020304, &s0, &s1, &sk);
    skey = sk[0];
    var mk: [2]M.Key = undefined;
    M.genWithSeeds(.{ 5, 77, 200 }, .{ 1, 2, 3 }, &ms0, &ms1, &mk) catch unreachable;
    mkey0 = mk[0];
    mkey1 = mk[1];
    key0.toBytes(&key_bytes);
    key1.toBytes(&key_bytes1);
    mkey0.toBytes(&mkey_bytes);
    key0.toBytesTagged(&tagged);
}

fn sinkEmit(c: *usize, x: usize, v: D.Elem) void {
    c.* +%= x +% v;
}
fn msinkEmit(c: *usize, x: usize, v: M.Elem) void {
    c.* +%= x +% v;
}
fn msinkEach(c: *usize, x: usize, v: *const [3]M.Elem) void {
    c.* +%= x +% v[0];
}

// Non-generic wrappers around the streaming (comptime-callback) entry points:
// they hold only the key pointer and public values.
fn dFullWith(key: *const D.Key, count: usize, c: *usize) void {
    D.evalFullWith(0, key, count, c, sinkEmit);
}
fn dRangeWith(key: *const D.Key, lo: usize, hi: usize, c: *usize) void {
    D.evalRangeWith(1, key, lo, hi, c, sinkEmit);
}
fn mFullWith(key: *const M.Key, count: usize, c: *usize) void {
    M.evalFullWith(0, key, count, c, msinkEmit);
}
fn mEachFullWith(key: *const M.Key, count: usize, c: *usize) void {
    M.evalEachFullWith(1, key, count, c, msinkEach);
}

test "STACKPROBE: no seed or key residue after any entry point" {
    try sp.skipUnlessOptimized();
    setup();
    const seeds = &[_][]const u8{ &s0, &s1 };
    const kb = &[_][]const u8{ &key_bytes, &key0.seed };
    const mseeds = &[_][]const u8{ &ms0[0], &ms0[1], &ms0[2], &ms1[0], &ms1[1], &ms1[2] };
    const mkb = &[_][]const u8{ &mkey_bytes, &mkey0.keys[0].seed, &mkey0.keys[1].seed, &mkey0.keys[2].seed };

    _ = try P.run("Dpf.genWithSeeds", D.genWithSeeds, .{ 333, 0x01020304, &s0, &s1, &gen_out }, seeds, .{});
    _ = try P.run("DpfSha.genWithSeeds", DS.genWithSeeds, .{ 333, 0x01020304, &s0, &s1, &sgen_out }, seeds, .{});
    _ = try P.run("Dpf.eval", D.eval, .{ 0, &key0, 333 }, kb, .{});
    _ = try P.run("Dpf.eval party 1", D.eval, .{ 1, &key1, 12 }, &[_][]const u8{ &key_bytes1, &key1.seed }, .{});
    _ = try P.run("DpfSha.eval", DS.eval, .{ 0, &skey, 333 }, &[_][]const u8{&skey.seed}, .{});
    _ = try P.run("Dpf.evalAll", D.evalAll, .{ 0, &key0, &evals }, kb, .{});
    _ = try P.run("Dpf.evalFull", D.evalFull, .{ 0, &key0, evals[0..700] }, kb, .{});
    _ = try P.run("Dpf.evalFullWith", dFullWith, .{ &key0, 700, &sink_count }, kb, .{});
    _ = try P.run("Dpf.evalRangeWith", dRangeWith, .{ &key1, 100, 600, &sink_count }, &[_][]const u8{ &key_bytes1, &key1.seed }, .{});
    _ = try P.run("Dpf.Key.toBytes", D.Key.toBytes, .{ &key0, &key_bytes }, kb, .{});
    _ = try P.run("Dpf.Key.serializeCw", D.Key.serializeCw, .{ &key0, &cw_bytes }, &[_][]const u8{&cw_bytes}, .{});
    _ = try P.run("Dpf.Key.toBytesTagged", D.Key.toBytesTagged, .{ &key0, &tagged }, &[_][]const u8{ &tagged, &key0.seed }, .{});
    _ = try P.run("Dpf.Key.fromBytes", D.Key.fromBytes, .{ &decoded, &key_bytes }, &[_][]const u8{ &key_bytes, &decoded.seed }, .{});
    _ = try P.run("Dpf.Key.fromBytesTagged", D.Key.fromBytesTagged, .{ &tagged_decoded, &tagged }, &[_][]const u8{ &tagged, &tagged_decoded.seed }, .{});
    try std.testing.expectEqualSlices(u8, &key0.seed, &decoded.seed);
    try std.testing.expectEqualSlices(u8, &key0.seed, &tagged_decoded.seed);

    _ = try P.run("Mpf.genWithSeeds", M.genWithSeeds, .{ .{ 5, 77, 200 }, .{ 1, 2, 3 }, &ms0, &ms1, &mgen_out }, mseeds, .{});
    _ = try P.run("Mpf.eval", M.eval, .{ 0, &mkey0, 77 }, mkb, .{});
    var each: [3]M.Elem = undefined;
    _ = try P.run("Mpf.evalEach", M.evalEach, .{ 0, &mkey0, 77, &each }, mkb, .{});
    _ = try P.run("Mpf.evalAll", M.evalAll, .{ 0, &mkey0, &mshares }, mkb, .{});
    _ = try P.run("Mpf.evalFull", M.evalFull, .{ 0, &mkey0, mshares[0..200] }, mkb, .{});
    _ = try P.run("Mpf.evalFullWith", mFullWith, .{ &mkey0, 200, &sink_count }, mkb, .{});
    _ = try P.run("Mpf.evalEachFullWith", mEachFullWith, .{ &mkey0, 200, &sink_count }, mkb, .{});
    _ = try P.run("Mpf.Key.toBytes", M.Key.toBytes, .{ &mkey0, &mkey_bytes }, mkb, .{});
    _ = try P.run("Mpf.Key.fromBytes", M.Key.fromBytes, .{ &mdecoded, &mkey_bytes }, &[_][]const u8{ &mkey_bytes, &mdecoded.keys[0].seed }, .{});
}
