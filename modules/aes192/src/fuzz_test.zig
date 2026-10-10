// SPDX-License-Identifier: MIT

//! The deterministic fuzz harness (testkit's driver): random key, random
//! blocks, every API path judged against the textbook model in
//! `model_test.zig` and against each other.
//!
//! Driver: `AES192_FUZZ=<runs>[,<first seed>]` (`_ONLY`, `_MS`, `_SEEDFILE`,
//! `_INPUT` as documented in testkit's `fuzz_driver.zig`). Harness name:
//! `aes192-cipher`. Without the variable the driver test skips; the
//! in-suite reach test below runs 300 seeds every time.
//!
//! Per input it checks, for one key and 1..9 blocks:
//!   * `encrypt` of each block == the model's CIPHER();
//!   * `encryptWide(n)` == n × `encrypt`; `decryptWide(n)` inverts it;
//!   * `decrypt` == the model's INVCIPHER() on the ciphertext (the module
//!     uses the equivalent inverse cipher, the model the plain one);
//!   * `xorWide(n)` with drawn counters == `encrypt(counter) ^ src`, and
//!     applying it twice is the identity;
//!   * `initEncInto`/`initDecInto` build the same schedules as `init*`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const root = @import("root.zig");
const model = @import("model_test.zig");

const Label = enum { one_block, wide, wide_max, decrypt_model, ctr };
var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    counts[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const max_blocks = 9;

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [24 + 2 * 16 * max_blocks + 1]u8 = undefined;
    const got = src.slice(&buf);
    // The input: key, then a block count, then data and counters. A short
    // input is zero-padded rather than refused, so every input runs.
    var in: [buf.len]u8 = @splat(0);
    @memcpy(in[0..got], buf[0..got]);
    const key: [24]u8 = in[0..24].*;
    const nblocks: usize = 1 + @as(usize, in[24]) % max_blocks;
    const data = in[25..][0 .. 16 * max_blocks];
    const ctrs = in[25 + 16 * max_blocks ..][0 .. 16 * max_blocks - 1].* ++ [1]u8{in[24]};

    const enc = root.Aes192.initEnc(key);
    const dec = root.Aes192.initDec(key);
    var e2: root.Aes192EncryptCtx = undefined;
    var d2: root.Aes192DecryptCtx = undefined;
    root.Aes192.initEncInto(&e2, &key);
    root.Aes192.initDecInto(&d2, &key);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&enc.key_schedule), std.mem.asBytes(&e2.key_schedule));
    try testing.expectEqualSlices(u8, std.mem.asBytes(&dec.key_schedule), std.mem.asBytes(&d2.key_schedule));

    var one: [16 * max_blocks]u8 = undefined;
    for (0..nblocks) |j| {
        const blk = data[j * 16 ..][0..16];
        enc.encrypt(one[j * 16 ..][0..16], blk);
        try testing.expectEqual(model.encrypt(&key, blk), one[j * 16 ..][0..16].*);
        var back: [16]u8 = undefined;
        dec.decrypt(&back, one[j * 16 ..][0..16]);
        try testing.expectEqualSlices(u8, blk, &back);
        dec.decrypt(&back, blk);
        try testing.expectEqual(model.decrypt(&key, blk), back);
    }
    mark(.one_block);
    mark(.decrypt_model);

    switch (nblocks) {
        inline 1...max_blocks => |n| {
            var wide: [16 * n]u8 = undefined;
            enc.encryptWide(n, &wide, data[0 .. 16 * n]);
            try testing.expectEqualSlices(u8, one[0 .. 16 * n], &wide);
            var back: [16 * n]u8 = undefined;
            dec.decryptWide(n, &back, &wide);
            try testing.expectEqualSlices(u8, data[0 .. 16 * n], &back);

            var want: [16 * n]u8 = undefined;
            for (0..n) |j| enc.encrypt(want[j * 16 ..][0..16], ctrs[j * 16 ..][0..16]);
            for (&want, data[0 .. 16 * n]) |*w, d| w.* ^= d;
            var x: [16 * n]u8 = undefined;
            enc.xorWide(n, &x, data[0 .. 16 * n], ctrs[0 .. 16 * n].*);
            try testing.expectEqualSlices(u8, &want, &x);
            var x2: [16 * n]u8 = undefined;
            enc.xorWide(n, &x2, &x, ctrs[0 .. 16 * n].*);
            try testing.expectEqualSlices(u8, data[0 .. 16 * n], &x2);
            var x1: [16]u8 = undefined;
            enc.xor(&x1, data[0..16], ctrs[0..16].*);
            try testing.expectEqualSlices(u8, want[0..16], &x1);
            mark(.wide);
            mark(.ctr);
            if (n == max_blocks) mark(.wide_max);
        },
        else => unreachable,
    }
}

test "fuzz driver: AES192_FUZZ (cipher)" {
    try fuzz_driver.run(harness, .{ .prefix = "AES192_FUZZ", .name = "aes192-cipher" });
}

test "fuzz harness: 300 seeds reach every check" {
    counts = @splat(0);
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("aes192-cipher seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (counts, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: aes192-cipher label {t} never hit\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}

test "fuzz: coverage-guided (std.testing.fuzz) over the same harness" {
    try testing.fuzz({}, struct {
        fn f(_: void, s: *testing.Smith) !void {
            return harness(testing.Smith, s, testing.allocator);
        }
    }.f, .{});
}
