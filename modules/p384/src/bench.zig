// SPDX-License-Identifier: MIT

//! bench — µs/op for key generation, ECDH, sign and verify. Off by default;
//! opt in with `P384_BENCH`:
//!
//!   P384_BENCH=1 zig build test-p384 -Doptimize=ReleaseFast
//!
//! Each figure is the best of 5 rounds (the noise floor on a laptop CPU).
//! The OpenSSL side is `openssl speed ecdsap384 ecdhp384` on the same host,
//! recorded in SPEC.md § Performance.

const std = @import("std");
const root = @import("root.zig");

const E = root.EcdsaP384Sha384;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn bestOf(comptime iters: usize, ctx: anytype, comptime f: fn (@TypeOf(ctx)) anyerror!void) !f64 {
    var best: u64 = std.math.maxInt(u64);
    for (0..5) |_| {
        const t0 = nowNs();
        for (0..iters) |_| try f(ctx);
        best = @min(best, nowNs() - t0);
    }
    return @as(f64, @floatFromInt(best)) / iters / 1000.0;
}

const Ctx = struct {
    kp: E.KeyPair,
    peer: [97]u8,
    sig: E.Signature,
    seed: [48]u8,
    msg: []const u8,
};

fn doKeygen(c: *Ctx) anyerror!void {
    c.seed[0] +%= 1;
    var kp: E.KeyPair = undefined;
    try E.KeyPair.generateDeterministicInto(&kp, &c.seed);
    std.mem.doNotOptimizeAway(&kp);
}

fn doEcdh(c: *Ctx) anyerror!void {
    var z: [48]u8 = undefined;
    try root.ecdhInto(&z, &c.kp.secret_key.bytes, &c.peer);
    std.mem.doNotOptimizeAway(&z);
}

fn doSign(c: *Ctx) anyerror!void {
    const s = try c.kp.sign(c.msg, null);
    std.mem.doNotOptimizeAway(&s);
}

fn doVerify(c: *Ctx) anyerror!void {
    try c.sig.verify(c.msg, c.kp.public_key);
}

test "bench (opt-in via P384_BENCH)" {
    if (@import("builtin").target.os.tag != .linux or std.testing.environ.getPosix("P384_BENCH") == null) return error.SkipZigTest;
    var c: Ctx = undefined;
    c.seed = @splat(0x42);
    c.msg = "p384 bench message";
    try E.KeyPair.generateDeterministicInto(&c.kp, &c.seed);
    var other: E.KeyPair = undefined;
    c.seed[1] = 7;
    try E.KeyPair.generateDeterministicInto(&other, &c.seed);
    c.peer = other.public_key.toUncompressedSec1();
    c.sig = try c.kp.sign(c.msg, null);

    const iters = 200;
    std.debug.print("\n=== p384 bench (best of 5 × {d}) ===\n", .{iters});
    std.debug.print("keygen  {d:8.1} us\n", .{try bestOf(iters, &c, doKeygen)});
    std.debug.print("ecdh    {d:8.1} us\n", .{try bestOf(iters, &c, doEcdh)});
    std.debug.print("sign    {d:8.1} us\n", .{try bestOf(iters, &c, doSign)});
    std.debug.print("verify  {d:8.1} us\n", .{try bestOf(iters, &c, doVerify)});
}

const SE = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const StdCtx = struct {
    kp: SE.KeyPair,
    peer: std.crypto.ecc.P384,
    sig: SE.Signature,
    msg: []const u8,
};

fn stdEcdh(c: *StdCtx) anyerror!void {
    const q = try c.peer.mul(c.kp.secret_key.bytes, .big);
    std.mem.doNotOptimizeAway(&q);
}

fn stdSign(c: *StdCtx) anyerror!void {
    const s = try c.kp.sign(c.msg, null);
    std.mem.doNotOptimizeAway(&s);
}

fn stdVerify(c: *StdCtx) anyerror!void {
    try c.sig.verify(c.msg, c.kp.public_key);
}

test "bench std P384 for comparison (opt-in via P384_BENCH)" {
    if (@import("builtin").target.os.tag != .linux or std.testing.environ.getPosix("P384_BENCH") == null) return error.SkipZigTest;
    var c: StdCtx = undefined;
    c.msg = "p384 bench message";
    c.kp = try SE.KeyPair.generateDeterministic(@splat(0x42));
    c.peer = (try SE.KeyPair.generateDeterministic(@splat(0x43))).public_key.p;
    c.sig = try c.kp.sign(c.msg, null);
    const iters = 100;
    std.debug.print("\n=== std.crypto P384 (best of 5 × {d}) ===\n", .{iters});
    std.debug.print("std ecdh   {d:8.1} us\n", .{try bestOf(iters, &c, stdEcdh)});
    std.debug.print("std sign   {d:8.1} us\n", .{try bestOf(iters, &c, stdSign)});
    std.debug.print("std verify {d:8.1} us\n", .{try bestOf(iters, &c, stdVerify)});
}

test "bench field (opt-in via P384_BENCH)" {
    if (@import("builtin").target.os.tag != .linux or std.testing.environ.getPosix("P384_BENCH") == null) return error.SkipZigTest;
    const Fe = @import("field.zig").Fe;
    var a = Fe.fromInt(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef) catch unreachable;
    const b = Fe.fromInt(0x0fedcba0987654320fedcba0987654320fedcba0987654320fedcba0987654320fedcba0987654320fedcba098765432) catch unreachable;
    const n = 1_000_000;
    var best_m: u64 = std.math.maxInt(u64);
    var best_s: u64 = std.math.maxInt(u64);
    for (0..5) |_| {
        var t0 = nowNs();
        for (0..n) |_| a = a.mul(b);
        best_m = @min(best_m, nowNs() - t0);
        t0 = nowNs();
        for (0..n) |_| a = a.sq();
        best_s = @min(best_s, nowNs() - t0);
    }
    std.mem.doNotOptimizeAway(&a);
    std.debug.print("fe.mul  {d:8.1} ns\nfe.sq   {d:8.1} ns\n", .{ @as(f64, @floatFromInt(best_m)) / n, @as(f64, @floatFromInt(best_s)) / n });
}
