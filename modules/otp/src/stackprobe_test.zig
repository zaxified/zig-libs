// SPDX-License-Identifier: MIT

//! Dead-stack probe for the secret-touching entry points (`testkit.stackprobe`):
//! residue below the burn, and the shared secret as a needle in any frame.
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode). Every code function funnels through
//! `dynamicTruncate`'s burn; probed through all three HMACs, the verify loop,
//! the `KeyUri` methods and the URI writer.

const std = @import("std");
const root = @import("root.zig");
const otpauth = @import("otpauth.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 64 * 1024 });

var secret: [64]u8 = undefined;
var code_buf: [8]u8 = undefined;
var uri_buf: [512]u8 = undefined;
var w: std.Io.Writer = undefined;

// The generic entry points take `comptime alg`, which the engine cannot take as
// a function type; these hold nothing but the arguments.
fn dt(comptime alg: root.Algorithm) fn ([]const u8, u64) u32 {
    return struct {
        fn f(k: []const u8, c: u64) u32 {
            return root.dynamicTruncate(alg, k, c);
        }
    }.f;
}

fn hotpFmt(comptime alg: root.Algorithm) fn ([]const u8, u64, []u8) root.FmtCodeError![]u8 {
    return struct {
        fn f(k: []const u8, c: u64, out: []u8) root.FmtCodeError![]u8 {
            return root.hotpFmt(alg, k, c, 8, out);
        }
    }.f;
}

fn verify(comptime alg: root.Algorithm) fn ([]const u8, u64, u32) bool {
    return struct {
        fn f(k: []const u8, t: u64, code: u32) bool {
            return root.totpVerify(alg, k, t, 30, 0, 8, code, 1);
        }
    }.f;
}

fn totpFmt(comptime alg: root.Algorithm) fn ([]const u8, u64, []u8) root.FmtCodeError![]u8 {
    return struct {
        fn f(k: []const u8, t: u64, out: []u8) root.FmtCodeError![]u8 {
            return root.totpFmt(alg, k, t, 30, 0, 8, out);
        }
    }.f;
}

test "STACKPROBE: no OTP secret residue after any entry point" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha512.hash("otp probe secret", &secret, .{});
    const ks = &[_][]const u8{&secret};
    const t: u64 = 1_760_000_000;

    inline for (.{ root.Algorithm.sha1, .sha256, .sha512 }) |alg| {
        const n = @tagName(alg);
        _ = try P.run("dynamicTruncate " ++ n, dt(alg), .{ &secret, 7 }, ks, .{});
        _ = try P.run("hotpFmt " ++ n, hotpFmt(alg), .{ &secret, 7, &code_buf }, ks, .{});
        _ = try P.run("totpFmt " ++ n, totpFmt(alg), .{ &secret, t, &code_buf }, ks, .{});
        const good = root.totp(alg, &secret, t, 30, 0, 8);
        _ = try P.run("totpVerify " ++ n, verify(alg), .{ &secret, t, good }, ks, .{});
    }

    const uri: otpauth.KeyUri = .{ .kind = .totp, .secret = &secret, .account = "alice", .issuer = "Example", .algorithm = .sha256, .digits = 8 };
    _ = try P.run("KeyUri.totpCode", otpauth.KeyUri.totpCode, .{ uri, t }, ks, .{});
    var hotp_uri = uri;
    hotp_uri.kind = .hotp;
    _ = try P.run("KeyUri.hotpCode", otpauth.KeyUri.hotpCode, .{ hotp_uri, 7 }, ks, .{});

    w = std.Io.Writer.fixed(&uri_buf);
    _ = try P.run("otpauth.format", otpauth.format, .{ &w, uri }, ks, .{});
}
