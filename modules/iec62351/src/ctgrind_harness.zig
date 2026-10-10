// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh iec62351`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-iec62351`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `mac` — the IEC 62351-6 GOOSE/SV MAC key tainted through
//!    `goose.computeMac` and `goose.verifyMac` (a valid tag and one with a
//!    flipped bit) for every MAC algorithm: HMAC-SHA256-80/128/256 and
//!    AES-GMAC-64/128 (AES-128 and AES-256 keys). The protected frame, the IV
//!    and the received tag are public.
//!
//! The RSASSA-PSS and ECDSA P-256 signature profiles delegate to the `rsa` and
//! `p256` modules, which carry their own rows.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const iec = @import("root.zig");

const goose = iec.goose;
const Target = enum { mac };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn one(alg: goose.MacAlgorithm, key: []const u8) void {
    const domain = "GOOSE PDU bytes covered by the MAC: header, APDU, extension";
    const iv: ?[12]u8 = if (alg.needsIv()) "ctgrind-iv12".* else null;
    var buf: [32]u8 = undefined;
    const tag = goose.computeMac(alg, key, domain, iv, &buf) catch unreachable;
    std.debug.print("ctgrind_result={x}\n", .{tag});
    // The received tag arrives on the wire: public.
    var wire: [32]u8 = undefined;
    @memcpy(wire[0..tag.len], tag);
    std.valgrind.memcheck.makeMemDefined(wire[0..tag.len]);
    const ok = goose.verifyMac(alg, key, domain, iv, wire[0..tag.len]);
    wire[0] ^= 0x01;
    const bad = goose.verifyMac(alg, key, domain, iv, wire[0..tag.len]);
    std.debug.print("ctgrind_result={x}\n", .{[2]u8{ @intFromBool(ok), @intFromBool(bad) }});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    switch (target) {
        .mac => {
            var k32 = secretBytes(32, "ctgrind-iec62351-key32-v1");
            var k16 = secretBytes(16, "ctgrind-iec62351-key16-v1");
            if (taint == .yes) {
                std.valgrind.memcheck.makeMemUndefined(&k32);
                std.valgrind.memcheck.makeMemUndefined(&k16);
            }
            one(.hmac_sha256_80, &k32);
            one(.hmac_sha256_128, &k32);
            one(.hmac_sha256_256, &k32);
            one(.aes_gmac_64, &k16);
            one(.aes_gmac_128, &k16);
            one(.aes_gmac_128, &k32);
        },
    }
}
