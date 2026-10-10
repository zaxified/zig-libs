// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh sha2`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-sha2`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! SHA-2 is unkeyed; what is secret is the MESSAGE (a key being hashed, an
//! HMAC key block, a password) — its length is public.
//!
//!  * `hash` — the message tainted through `hash` and through `update` in
//!    uneven pieces, for SHA-224/256/384/512, at lengths 0..2 blocks plus a
//!    multi-block message (the batched-schedule path), and `peek`.
//!  * `hmac` — `std.crypto.auth.hmac.Hmac` instantiated over this module's
//!    `Sha256` and `Sha512` with the key and the message tainted.
//!
//! The backend is whichever `backend()` picks under valgrind's CPU model.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const sha2 = @import("root.zig");

const Target = enum { hash, hmac };
const Taint = enum { yes, no };

fn message(comptime n: usize) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
    return out;
}

fn hashAll(comptime H: type, t: Taint) void {
    var msg = message(1000);
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(&msg);
    std.debug.print("backend={t}\n", .{H.backend()});
    for ([_]usize{ 0, 1, 55, 56, 64, 111, 112, 128, 129, 1000 }) |n| {
        var out: [H.digest_length]u8 = undefined;
        H.hash(msg[0..n], &out, .{});
        std.debug.print("ctgrind_result={x}\n", .{out});
    }
    var h = H.init(.{});
    h.update(msg[0..3]);
    h.update(msg[3..200]);
    const mid = h.peek();
    h.update(msg[200..]);
    std.debug.print("ctgrind_result={x}\n", .{mid ++ h.finalResult()});
}

fn hmacOne(comptime H: type, t: Taint) void {
    const M = std.crypto.auth.hmac.Hmac(H);
    var key = message(32);
    var msg = message(300);
    if (t == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&key);
        std.valgrind.memcheck.makeMemUndefined(&msg);
    }
    var mac: [M.mac_length]u8 = undefined;
    M.create(&mac, &msg, &key);
    std.debug.print("ctgrind_result={x}\n", .{mac});
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
        .hash => {
            hashAll(sha2.Sha224, taint);
            hashAll(sha2.Sha256, taint);
            hashAll(sha2.Sha384, taint);
            hashAll(sha2.Sha512, taint);
        },
        .hmac => {
            hmacOne(sha2.Sha256, taint);
            hmacOne(sha2.Sha512, taint);
        },
    }
}
