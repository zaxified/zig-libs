// SPDX-License-Identifier: MIT

//! Comparative benchmark: `ed448` against OpenSSL's Ed448 and X448 (the
//! reference), the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-ed448` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs `openssl` on PATH
//! (its `speed` command; the version is printed). Run from the repository root.
//!
//! OpenSSL's side is `openssl speed -seconds 3 -mr ed448 ecdhx448`: its own
//! loop over sign, verify and X448 derive, reported as operations per second.
//! Ours: the same three operations (sign and verify over a 64-byte message,
//! no context), timed by doubling the batch until it takes over 100 ms and
//! keeping the best of five. The two loops differ in shape — OpenSSL averages
//! over three seconds, ours keeps the best batch — so a ratio within a few
//! per cent of 1 is a tie, not a result. No answer is compared here: the
//! values are anchored by the RFC 8032/7748 KATs in `src/`.

const std = @import("std");
const lib = @import("ed448");
const ed = lib.ed448;
const x448 = lib.x448;

fn timeIt(io: std.Io, ctx: anytype, comptime f: anytype) f64 {
    var n: usize = 1;
    while (true) {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(@call(.auto, f, ctx));
        if (t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds > 100_000_000) break;
        n *= 2;
    }
    var best: i96 = std.math.maxInt(i96);
    for (0..5) |_| {
        const t = std.Io.Clock.Timestamp.now(io, .awake);
        for (0..n) |_| std.mem.doNotOptimizeAway(@call(.auto, f, ctx));
        best = @min(best, t.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.nanoseconds);
    }
    return @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(n));
}

const msg = [_]u8{0x5a} ** 64;

fn doSign(kp: *const ed.KeyPair) ed.Signature {
    return ed.sign(kp, &msg, "") catch unreachable;
}
fn doVerify(sig: ed.Signature, pk: ed.PublicKey) bool {
    ed.verify(sig, &msg, "", pk) catch return false;
    return true;
}
fn doDerive(sk: *const [x448.scalar_length]u8, pk: [x448.public_length]u8) [x448.shared_length]u8 {
    var out: [x448.shared_length]u8 = undefined;
    x448.scalarmult(&out, sk, pk) catch unreachable;
    return out;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    std.debug.print("bench-ed448: openssl speed (about 10 s) ...\n", .{});
    const ver = std.process.run(arena, io, .{ .argv = &.{ "openssl", "version" } }) catch |e| {
        std.debug.print("bench-ed448: could not run openssl ({t})\n", .{e});
        return 1;
    };
    const res = try std.process.run(arena, io, .{ .argv = &.{ "openssl", "speed", "-seconds", "3", "-mr", "ed448", "ecdhx448" } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("bench-ed448: openssl speed failed:\n{s}\n", .{res.stderr});
        return 1;
    }
    // `+F6:<i>:456:Ed448:<sign/s>:<verify/s>` and `+F5:<i>:448:<derive/s>:…`
    var sign_rate: ?f64 = null;
    var verify_rate: ?f64 = null;
    var derive_rate: ?f64 = null;
    var lines = std.mem.tokenizeScalar(u8, res.stdout, '\n');
    while (lines.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        const tag = f.next().?;
        if (std.mem.eql(u8, tag, "+F6")) {
            _ = f.next();
            _ = f.next();
            if (!std.mem.eql(u8, f.next() orelse "", "Ed448")) continue;
            sign_rate = try std.fmt.parseFloat(f64, f.next() orelse return error.BadOpensslOutput);
            verify_rate = try std.fmt.parseFloat(f64, f.next() orelse return error.BadOpensslOutput);
        } else if (std.mem.eql(u8, tag, "+F5")) {
            _ = f.next();
            if (!std.mem.eql(u8, f.next() orelse "", "448")) continue;
            derive_rate = try std.fmt.parseFloat(f64, f.next() orelse return error.BadOpensslOutput);
        }
    }
    if (sign_rate == null or derive_rate == null) {
        std.debug.print("bench-ed448: no Ed448/X448 rows in openssl's output:\n{s}\n", .{res.stdout});
        return 1;
    }

    const kp = ed.KeyPair.create(&([_]u8{7} ** 57));
    const sig = doSign(&kp);
    if (!doVerify(sig, kp.public_key)) return error.OwnSignatureDoesNotVerify;
    var a: x448.KeyPair = undefined;
    try x448.KeyPair.generateDeterministic(&a, &([_]u8{9} ** x448.seed_length));
    var b: x448.KeyPair = undefined;
    try x448.KeyPair.generateDeterministic(&b, &([_]u8{3} ** x448.seed_length));

    const rows = [_]struct { name: []const u8, ours: f64, theirs: f64 }{
        .{ .name = "sign", .ours = timeIt(io, .{&kp}, doSign), .theirs = 1e9 / sign_rate.? },
        .{ .name = "verify", .ours = timeIt(io, .{ sig, kp.public_key }, doVerify), .theirs = 1e9 / verify_rate.? },
        .{ .name = "x448", .ours = timeIt(io, .{ &a.secret_key, b.public_key }, doDerive), .theirs = 1e9 / derive_rate.? },
    };

    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    try w.print("reference: {s}", .{ver.stdout});
    try w.print("{s:<8} {s:>12} {s:>14} {s:>13}\n", .{ "op", "ours ns/op", "openssl ns/op", "ours/openssl" });
    var worst: f64 = 0;
    var best: f64 = std.math.inf(f64);
    for (rows) |r| {
        const ratio = r.ours / r.theirs;
        worst = @max(worst, ratio);
        best = @min(best, ratio);
        try w.print("{s:<8} {d:>12.0} {d:>14.0} {d:>13.2}\n", .{ r.name, r.ours, r.theirs, ratio });
    }
    try w.print("\nworst ours/openssl = {d:.2} (best {d:.2})\n", .{ worst, best });
    try w.print("card: **Performance:** ref {d:.2}–{d:.2}× OpenSSL <version> Ed448/X448 · fastest ? (measured <today>)\n", .{ best, worst });
    try w.flush();
    return 0;
}
