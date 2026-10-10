// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh base32`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-base32`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! base32 carries secrets in practice — the TOTP/HOTP shared secret of an
//! `otpauth://` URI (`otp`) is base32 — so the data bytes are the secret; the
//! length, the options and where padding goes are public.
//!
//!  * `encode` — a tainted 20-byte secret (and 1..5-byte tails) through
//!    `encode` for both alphabets, padded and unpadded, upper and lower case.
//!  * `decode` — the tainted encoded text of a secret through `decode` for
//!    both alphabets, padding required/optional, case upper-only/insensitive
//!    (lower-case input), plus one input with an invalid character (rejected:
//!    validity is a verdict on the whole text).
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const b32 = @import("root.zig");

const Target = enum { encode, decode };
const Taint = enum { yes, no };

fn secret() [20]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ctgrind-base32-secret-v1", &full, .{});
    return full[0..20].*;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    const alphabets = [_]b32.Alphabet{ .std, .hex };

    switch (target) {
        .encode => {
            var s = secret();
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&s);
            for (alphabets) |alph| for ([_]bool{ true, false }) |pad| for ([_]bool{ false, true }) |lower| {
                for ([_]usize{ 20, 1, 2, 3, 4 }) |n| {
                    var out: [40]u8 = undefined;
                    const text = try b32.encode(&out, s[0..n], .{ .alphabet = alph, .pad = pad, .lowercase = lower });
                    std.debug.print("ctgrind_result={x}\n", .{text});
                }
            };
        },
        .decode => {
            const s = secret();
            for (alphabets) |alph| {
                // Build the texts untainted, then taint them: the encoded
                // secret is as secret as the secret.
                var up: [32]u8 = undefined;
                const t_up = try b32.encode(&up, &s, .{ .alphabet = alph, .pad = true });
                var low: [32]u8 = undefined;
                const t_low = try b32.encode(&low, &s, .{ .alphabet = alph, .pad = false, .lowercase = true });
                if (taint == .yes) {
                    std.valgrind.memcheck.makeMemUndefined(up[0..t_up.len]);
                    std.valgrind.memcheck.makeMemUndefined(low[0..t_low.len]);
                }
                var out: [20]u8 = undefined;
                var n = try b32.decode(&out, up[0..t_up.len], .{ .alphabet = alph, .padding = .required });
                std.debug.print("ctgrind_result={x}\n", .{out[0..n]});
                n = try b32.decode(&out, low[0..t_low.len], .{ .alphabet = alph, .padding = .optional, .case = .insensitive });
                std.debug.print("ctgrind_result={x}\n", .{out[0..n]});
                var bad = up;
                bad[5] = '!';
                const rej = if (b32.decode(&out, bad[0..t_up.len], .{ .alphabet = alph })) |_| false else |_| true;
                std.debug.print("ctgrind_result={x}\n", .{[1]u8{@intFromBool(rej)}});
            }
        },
    }
}
