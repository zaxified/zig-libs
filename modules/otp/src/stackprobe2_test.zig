// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of `hotpVerify` and `hotpResync`,
//! the HOTP verifiers `stackprobe_test.zig` does not call: residue below each
//! burn, the OTP secret as a needle. Each runs its whole look-ahead window
//! (a code that never matches), so every HMAC of the window is measured.
//! ReleaseFast/ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var secret: [64]u8 = undefined;

fn hv(comptime alg: root.Algorithm) fn ([]const u8, u64, u32) root.HotpVerifyError!?u64 {
    return struct {
        fn f(k: []const u8, c: u64, code: u32) root.HotpVerifyError!?u64 {
            return root.hotpVerify(alg, k, c, 8, code, 10);
        }
    }.f;
}

fn hr(comptime alg: root.Algorithm) fn ([]const u8, u64, u32, u32) root.HotpVerifyError!?u64 {
    return struct {
        fn f(k: []const u8, c: u64, c1: u32, c2: u32) root.HotpVerifyError!?u64 {
            return root.hotpResync(alg, k, c, 8, c1, c2, 10);
        }
    }.f;
}

test "STACKPROBE: hotpVerify and hotpResync leave no OTP secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha512.hash("otp probe2 secret", &secret, .{});
    const ks = &[_][]const u8{&secret};
    inline for (.{ root.Algorithm.sha1, .sha256, .sha512 }) |alg| {
        const n = @tagName(alg);
        // 100_000_000 is not an 8-digit code: no counter in the window matches.
        _ = try P.run("hotpVerify (no match) " ++ n, hv(alg), .{ &secret, 7, 100_000_000 }, ks, .{});
        const good = root.hotp(alg, &secret, 9, 8);
        _ = try P.run("hotpVerify (match) " ++ n, hv(alg), .{ &secret, 7, good }, ks, .{});
        _ = try P.run("hotpResync " ++ n, hr(alg), .{ &secret, 7, good, root.hotp(alg, &secret, 10, 8) }, ks, .{});
    }
}
