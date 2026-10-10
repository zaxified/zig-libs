// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for mls (added 2026-10-10): `MLS_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `mls-decode` (KeyPackage / Welcome / Commit MLSMessages from a real
//! exchange, damaged, through the decoders) and `mls-group` (a two-member
//! group: a genuine Welcome joins and a genuine Commit advances the member,
//! every flipped bit refused, a refused Commit leaves the member able to take
//! the genuine one, a damaged one accepted only when byte-identical).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
pub const Cursor = testkit.fuzz.Cursor;

/// Reach counters for one harness's labels. `mark` also feeds the driver's
/// `REACH` report; `reach` runs `seeds` seeds in the ordinary test binary and
/// fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Deterministic bytes from a knob cursor (its first octets seed a PRNG).
pub fn expand(knobs: *Cursor, out: []u8) void {
    var s: u64 = 0;
    for (0..8) |_| s = (s << 8) | knobs.byte();
    var prng = std.Random.DefaultPrng.init(s);
    prng.random().bytes(out);
}

/// Smith-side wrapper so `--fuzz` keeps working: the harness bodies are
/// generic over `S`; `testing.fuzz` hands them a `std.testing.Smith`.
pub fn smithWrap(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

const suite = @import("suite.zig");
const codec = @import("codec.zig");
const framing = @import("framing.zig");
const keypackage_mod = @import("keypackage.zig");
const welcome_mod = @import("welcome.zig");
const Suite = suite.default;
const Group = @import("group.zig").Group(Suite);

const Client = struct {
    sig: Suite.Sig.KeyPair,
    init_priv: [Suite.Kem.Nsk]u8,
    enc_priv: [Suite.Kem.Nsk]u8,
    kp_msg: []u8,
    kp: keypackage_mod.KeyPackage,

    fn init(arena: std.mem.Allocator, name: []const u8, seed: u8) !Client {
        const sig = try Suite.Sig.KeyPair.generateDeterministic(@splat(seed));
        const init_kp = try Suite.Kem.KeyPair.generateDeterministic(@splat(seed +% 64));
        const enc_kp = try Suite.Kem.KeyPair.generateDeterministic(@splat(seed +% 128));
        const kp = try keypackage_mod.create(Suite, arena, .{
            .signature_key_pair = &sig,
            .init_key = init_kp.public_key,
            .encryption_key = enc_kp.public_key,
            .credential = .{ .basic = name },
            .capabilities = .{
                .versions = &.{1},
                .cipher_suites = &.{1},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{1},
            },
            .lifetime = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
        });
        const msg: framing.MLSMessage = .{ .key_package = kp };
        return .{
            .sig = sig,
            .init_priv = init_kp.secret_key,
            .enc_priv = enc_kp.secret_key,
            .kp_msg = try msg.encodeAlloc(arena),
            .kp = kp,
        };
    }

    fn join(self: Client, gpa: std.mem.Allocator, welcome_msg: []const u8, out: *Group) !void {
        return Group.fromWelcome(gpa, .{
            .welcome_msg = welcome_msg,
            .key_package_msg = self.kp_msg,
            .init_priv = &self.init_priv,
            .encryption_priv = &self.enc_priv,
        }, out);
    }
};

fn flipBit(knobs: *Cursor, bytes: []u8) void {
    const at = (@as(usize, knobs.byte()) << 8 | knobs.byte()) % bytes.len;
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
}

fn sameEpoch(a: *const Group, b: *const Group) bool {
    var ea: [Suite.Nh]u8 = undefined;
    var eb: [Suite.Nh]u8 = undefined;
    a.epochAuthenticator(&ea);
    b.epochAuthenticator(&eb);
    return a.epoch == b.epoch and std.mem.eql(u8, &a.tree_hash, &b.tree_hash) and std.mem.eql(u8, &ea, &eb);
}

/// Decode `bytes` as an MLSMessage and, when it is a KeyPackage / Welcome /
/// GroupInfo-bearing message, nothing else is run: decoding must not panic.
fn decodeOnly(arena: std.mem.Allocator, bytes: []const u8) bool {
    var r = codec.Reader.init(bytes);
    _ = framing.MLSMessage.decode(arena, &r) catch return false;
    return true;
}

const DecodeMark = Marker(enum { kp_ok, kp_refused, welcome_ok, welcome_refused, commit_ok, commit_refused });

fn fuzzDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [8]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const aa = arena_state.allocator();
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const seed_a: u8 = knobs.byte();
    const alice = try Client.init(aa, "alice", seed_a);
    const bob = try Client.init(aa, "bob", seed_a +% 1);
    var a: Group = undefined;
    try Group.create(gpa, .{ .io = io, .group_id = "fuzz", .key_package_msg = alice.kp_msg, .encryption_priv = &alice.enc_priv }, &a);
    defer a.deinit();
    const created = try a.createCommit(gpa, .{ .io = io, .signature_key_pair = &alice.sig, .proposals = &.{.{ .by_value = .{ .add = bob.kp } }} });
    defer created.deinit(gpa);

    var buf: [8192]u8 = undefined;
    const frames = [_][]const u8{ alice.kp_msg, created.welcome.?, created.commit };
    const which = knobs.ranged(0, 2);
    const n = damage(src, &buf, frames[which]);
    const ok = decodeOnly(aa, buf[0..n]);
    switch (which) {
        0 => if (ok) DecodeMark.mark(.kp_ok) else DecodeMark.mark(.kp_refused),
        1 => if (ok) DecodeMark.mark(.welcome_ok) else DecodeMark.mark(.welcome_refused),
        else => if (ok) DecodeMark.mark(.commit_ok) else DecodeMark.mark(.commit_refused),
    }
    // A damaged Welcome and a damaged KeyPackage through the joiner too: no panic.
    var g: Group = undefined;
    if (which == 1) {
        if (bob.join(gpa, buf[0..n], &g)) {
            g.deinit();
            if (!std.mem.eql(u8, buf[0..n], frames[1])) return error.DamagedWelcomeJoined;
        } else |_| {}
    }
}

test "fuzz: mls decoders on damaged genuine messages" {
    try testing.fuzz({}, smithWrap(fuzzDecode), .{});
}
test "fuzz driver: MLS_FUZZ (decode)" {
    try fuzz_driver.run(fuzzDecode, .{ .prefix = "MLS_FUZZ", .name = "mls-decode", .scale = 8 });
}
test "fuzz harness: decode, 60 seeds, reaches every outcome" {
    try DecodeMark.reach(fuzzDecode, "mls-decode", 60);
}

const GroupMark = Marker(enum { welcome_joined, flipped_welcome_refused, commit_applied, flipped_commit_refused, refused_then_genuine, damaged_commit_refused, with_add });

fn fuzzGroup(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [8]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const aa = arena_state.allocator();
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const seed_a: u8 = knobs.byte();
    const alice = try Client.init(aa, "alice", seed_a);
    const bob = try Client.init(aa, "bob", seed_a +% 1);
    const carol = try Client.init(aa, "carol", seed_a +% 2);
    var a: Group = undefined;
    try Group.create(gpa, .{ .io = io, .group_id = "fuzz", .key_package_msg = alice.kp_msg, .encryption_priv = &alice.enc_priv }, &a);
    defer a.deinit();
    const c1 = try a.createCommit(gpa, .{ .io = io, .signature_key_pair = &alice.sig, .proposals = &.{.{ .by_value = .{ .add = bob.kp } }} });
    defer c1.deinit(gpa);

    // A flipped Welcome joins no one.
    {
        const bad = try gpa.dupe(u8, c1.welcome.?);
        defer gpa.free(bad);
        flipBit(&knobs, bad);
        var g: Group = undefined;
        if (bob.join(gpa, bad, &g)) {
            g.deinit();
            return error.FlippedWelcomeAccepted;
        } else |_| GroupMark.mark(.flipped_welcome_refused);
    }
    var b: Group = undefined;
    bob.join(gpa, c1.welcome.?, &b) catch return error.GenuineWelcomeRefused;
    defer b.deinit();
    if (!sameEpoch(&a, &b)) return error.WelcomeEpochDiffers;
    GroupMark.mark(.welcome_joined);

    // The second Commit: empty (update path) or adding carol.
    const add_carol = knobs.byte() & 1 == 1;
    const c2 = if (add_carol)
        try a.createCommit(gpa, .{ .io = io, .signature_key_pair = &alice.sig, .proposals = &.{.{ .by_value = .{ .add = carol.kp } }} })
    else
        try a.createCommit(gpa, .{ .io = io, .signature_key_pair = &alice.sig });
    defer c2.deinit(gpa);
    if (add_carol) GroupMark.mark(.with_add);

    {
        const bad = try gpa.dupe(u8, c2.commit);
        defer gpa.free(bad);
        flipBit(&knobs, bad);
        if (b.processCommit(.{ .commit_msg = bad })) |_| return error.FlippedCommitAccepted else |_| GroupMark.mark(.flipped_commit_refused);
        var buf: [8192]u8 = undefined;
        const n = damage(src, &buf, c2.commit);
        if (b.processCommit(.{ .commit_msg = buf[0..n] })) |_| {
            // Accepted only when the damage left the bytes alone; the member
            // is then already in the new epoch and the genuine copy is a replay.
            if (!std.mem.eql(u8, buf[0..n], c2.commit)) return error.DamagedCommitAccepted;
            if (!sameEpoch(&a, &b)) return error.CommitEpochDiffers;
            GroupMark.mark(.commit_applied);
            return;
        } else |_| GroupMark.mark(.damaged_commit_refused);
    }
    // Refusals are atomic: the member still takes the genuine Commit.
    b.processCommit(.{ .commit_msg = c2.commit }) catch return error.GenuineCommitRefusedAfterDamage;
    if (!sameEpoch(&a, &b)) return error.CommitEpochDiffers;
    GroupMark.mark(.refused_then_genuine);
    GroupMark.mark(.commit_applied);
}

test "fuzz: mls group, genuine Welcome/Commit accepted, flipped refused" {
    try testing.fuzz({}, smithWrap(fuzzGroup), .{});
}
test "fuzz driver: MLS_FUZZ (group)" {
    try fuzz_driver.run(fuzzGroup, .{ .prefix = "MLS_FUZZ", .name = "mls-group", .scale = 8 });
}
test "fuzz harness: group, 40 seeds, reaches every outcome" {
    try GroupMark.reach(fuzzGroup, "mls-group", 40);
}
