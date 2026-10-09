// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh stun`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-stun`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The module's secrets are the credential behind MESSAGE-INTEGRITY:
//!
//!  * `mi` — the HMAC-SHA1 key (the short-term password, or a long-term key).
//!    Tainted, then `Builder.addMessageIntegrity` on a request carrying
//!    USERNAME and SOFTWARE, and `Message.verifyMessageIntegrity` on that
//!    message and on a copy with one SOFTWARE byte flipped (rejected on the
//!    MAC compare, not on parsing). Message bytes, lengths and attribute
//!    layout are public and stay defined; FINGERPRINT is deliberately not
//!    added — it is a CRC over the (public, on-the-wire) MAC, and a tainted
//!    MAC through std's table CRC would be an artefact, not a leak.
//!  * `ltkey` — the password in `longTermKey` (MD5(user ":" realm ":" pw),
//!    RFC 8489 §9.2.2). Username and realm are public.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const stun = @import("root.zig");

const Target = enum { mi, ltkey };
const Taint = enum { yes, no };

/// A runtime (not comptime-foldable) stand-in for a secret.
fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn reloadVolatile(comptime n: usize, src: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const txid: stun.TransactionId = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc };

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .mi => {
            // 20 B: a typical short-term password length (ICE pwd is 22+).
            var raw = secretBytes(20, "ctgrind-stun-mi-key-v1");
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
            const key = reloadVolatile(20, &raw);

            var buf: [256]u8 = undefined;
            var b = try stun.Builder.init(&buf, .request, .binding, txid);
            try b.addUsername("alice:bob");
            try b.addSoftware("ctgrind harness");
            try b.addMessageIntegrity(&key);
            const wire = b.finish();

            const ok_good = (try stun.decode(wire)).verifyMessageIntegrity(&key);
            var tampered: [256]u8 = undefined;
            @memcpy(tampered[0..wire.len], wire);
            // Byte 20 is the first attribute's type; 20+4+12 is inside the
            // SOFTWARE value (USERNAME "alice:bob" pads to 12).
            tampered[20 + 4 + 12 + 4] ^= 0x01;
            const ok_bad = (try stun.decode(tampered[0..wire.len])).verifyMessageIntegrity(&key);

            const mac = wire[wire.len - 20 ..][0..20].*;
            var res: [22]u8 = undefined;
            @memcpy(res[0..20], &mac);
            res[20] = @intFromBool(ok_good);
            res[21] = @intFromBool(ok_bad);
            std.debug.print("ctgrind_result={x}\n", .{res});
        },
        .ltkey => {
            var raw = secretBytes(24, "ctgrind-stun-password-v1");
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
            const password = reloadVolatile(24, &raw);
            var out: [16]u8 = undefined;
            stun.longTermKey(&out, "user", "example.org", &password);
            std.debug.print("ctgrind_result={x}\n", .{out});
        },
    }
}
