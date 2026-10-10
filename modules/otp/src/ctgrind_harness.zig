// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh otp`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-otp`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `code` — the shared secret tainted through `hotp`, `totp`, `hotpFmt`
//!    and `totpVerify` (valid and wrong code, ±1 step) for SHA-1, SHA-256
//!    and SHA-512. The code is a secret too (a live credential), so its
//!    formatting is in scope. Until 2026-10-10 the dynamic truncation read
//!    the 4 code bytes at `mac[offset]`, an index derived from the MAC under
//!    the secret key; `truncateCt` selects them with masks.
//!  * `uri` — `otpauth.format` writing a key URI whose secret is tainted (the
//!    secret is written as base32 by the `base32` module) and `KeyUri.totpCode`.
//!
//! The counter, time, digits and period are public.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const otp = @import("root.zig");

const Target = enum { code, uri };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var key = secretBytes(20, "ctgrind-otp-secret-v1");
    if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&key);

    switch (target) {
        .code => {
            inline for (.{ otp.Algorithm.sha1, otp.Algorithm.sha256, otp.Algorithm.sha512 }) |alg| {
                const h = otp.hotp(alg, &key, 1, 6);
                const t = otp.totp(alg, &key, 59, 30, 0, 8);
                var buf: [8]u8 = undefined;
                const s = try otp.hotpFmt(alg, &key, 7, 8, &buf);
                // The submitted code is the attacker's input: public.
                const ok = otp.totpVerify(alg, &key, 1_111_111_109, 30, 0, 8, 12345678, 1);
                std.debug.print("ctgrind_result={x}\n", .{std.mem.toBytes(h) ++ std.mem.toBytes(t) ++ [1]u8{@intFromBool(ok)}});
                std.debug.print("ctgrind_result={x}\n", .{s});
            }
        },
        .uri => {
            const k: otp.otpauth.KeyUri = .{
                .kind = .totp,
                .secret = &key,
                .account = "alice@example.com",
                .issuer = "Example",
                .algorithm = .sha256,
                .digits = 8,
            };
            var out: [otp.otpauth.max_uri_len]u8 = undefined;
            var w: std.Io.Writer = .fixed(&out);
            try otp.otpauth.format(&w, k);
            std.debug.print("ctgrind_result={x}\n", .{w.buffered()});
            std.debug.print("ctgrind_result={x}\n", .{std.mem.toBytes(try k.totpCode(59))});
        },
    }
}
