// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of every CCM entry point —
//! `init`, `seal`, `open`, `encrypt`, `decrypt` — for AES-128, AES-192 and
//! AES-256 (SPEC Backlog item, coverage sweep 2026-11-26). CCM carries no
//! burn (std's AEAD shape), so `.burn = false` and the needles are the check:
//! the expanded key schedule's round keys 1..Nr (round key 0 IS the key,
//! whose by-value copy in the caller's frame the `[key_length]u8` parameter
//! makes by shape), the plaintext, and for `open` the plaintext it writes.
//! ReleaseFast/ReleaseSmall only (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

fn Suite(comptime C: type, comptime Aes: type, comptime name: []const u8) type {
    return struct {
        var key: [C.key_length]u8 = undefined;
        var rks: [@sizeOf(@TypeOf(Aes.initEnc(@as([C.key_length]u8, undefined))))]u8 = undefined;
        var m: [100]u8 = undefined;
        var c: [100]u8 = undefined;
        var back: [100]u8 = undefined;
        var tag: [C.tag_length]u8 = undefined;
        var s: C = undefined;
        const npub: [C.nonce_length]u8 = @splat(0x42);

        fn initW(k: *const [C.key_length]u8) C {
            return C.init(k.*);
        }
        fn sealW(st: *const C) !void {
            return st.seal(&c, &tag, &m, "ad", npub);
        }
        fn openW(st: *const C) !void {
            return st.open(&back, &c, tag, "ad", npub);
        }
        fn encW(k: *const [C.key_length]u8) !void {
            return C.encrypt(&c, &tag, &m, "ad", npub, k.*);
        }
        fn decW(k: *const [C.key_length]u8) !void {
            return C.decrypt(&back, &c, tag, "ad", npub, k.*);
        }

        fn probe() !void {
            var h: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash("aesccm probe key " ++ name, &h, .{});
            key = h[0..C.key_length].*;
            std.crypto.hash.sha2.Sha512.hash("aesccm probe plaintext " ++ name, &h, .{});
            for (&m, 0..) |*b, i| b.* = h[i % 64] ^ @as(u8, @truncate(i / 64));
            const ctx = Aes.initEnc(key);
            rks = std.mem.toBytes(ctx);
            const schedule = rks[16..]; // round keys 1..Nr
            const no_burn: sp.Expect = .{ .burn = false };

            // `init` returns the context by value: its round keys land in the probe's
            // call frame by shape, so only the absence of residue below is checked.
            _ = try P.run(name ++ " init", initW, .{&key}, &.{}, .{ .burn = false, .residue = false });
            s = C.init(key);
            _ = try P.run(name ++ " seal", sealW, .{&s}, &.{ schedule, &m }, no_burn);
            _ = try P.run(name ++ " open", openW, .{&s}, &.{ schedule, &m, &back }, no_burn);
            _ = try P.run(name ++ " encrypt", encW, .{&key}, &.{ schedule, &m }, no_burn);
            _ = try P.run(name ++ " decrypt", decW, .{&key}, &.{ schedule, &m, &back }, no_burn);
            try std.testing.expectEqualSlices(u8, &m, &back);
            s.deinit();
        }
    };
}

test "STACKPROBE: CCM init/seal/open/encrypt/decrypt leave no key schedule or plaintext on the dead stack" {
    try sp.skipUnlessOptimized();
    try Suite(root.Aes128Ccm, std.crypto.core.aes.Aes128, "AES-128-CCM").probe();
    try Suite(root.Aes192Ccm, @import("aes192").Aes192, "AES-192-CCM").probe();
    try Suite(root.Aes256Ccm8, std.crypto.core.aes.Aes256, "AES-256-CCM8").probe();
}
