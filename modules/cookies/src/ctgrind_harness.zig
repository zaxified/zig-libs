// SPDX-License-Identifier: MIT

//! ctgrind_harness — the measurement behind `SPEC.md`'s constant-time note
//! for `secure.zig`. Run it through `../../../scripts/checks/ctgrind.sh
//! cookies`, which builds it with and without `-fvalgrind`, runs every target
//! tainted and untainted, and prints the control table.
//!
//! ## What is tainted
//!
//! The derivation master (`derive`), the `Key` (every target) and, for
//! `seal`, the plaintext value. Name, nonce, the presented signed/sealed value
//! and lengths stay defined: they are public by the cookie's contract.
//!
//! ## What the honest count is
//!
//! - `derive`, `sign`, `seal`: 0 in-file. `sign` and `seal` declassify their
//!   output (tag; ciphertext ‖ tag) inside `secure.zig` before base64, because
//!   it is sent to the client — that declassification is part of the claim.
//! - `verify`, `open`: the accept/reject verdict and nothing else (counted by
//!   the table, itemised in SPEC.md). The harness declassifies the verdict
//!   before its own branch on it.
//!
//! ReleaseFast only (the driver's default), `reload` forces a real load from
//! tainted memory. `derive`, `verify` and `open` print a tainted result as the
//! propagation witness; `sign` and `seal` cannot (their output is declassified
//! inside the module by design), so their rows pin `total_min` 0 and rely on
//! the output digest to prove the module was reached.

const std = @import("std");
const builtin = @import("builtin");
const secure = @import("secure.zig");

const Target = enum { derive, sign, verify, seal, open };

fn reload(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next();
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = std.meta.stringToEnum(Target, target_arg) orelse return error.UnknownTarget;
    const taint = if (std.mem.eql(u8, taint_arg, "yes")) true else if (std.mem.eql(u8, taint_arg, "no")) false else return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var master_mem: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash("ctgrind-cookies-harness-master-v1", &master_mem, .{});
    var value_mem: [300]u8 = undefined;
    for (&value_mem, 0..) |*b, i| b.* = "abcdefghijklmnopqrstuvwxyz0123456789"[i % 36];

    // Public values made from the UNTAINTED key first.
    var pub_key: secure.Key = undefined;
    try secure.Key.deriveInto(&pub_key, &master_mem);
    var signed_buf: [400]u8 = undefined;
    const signed_v = try secure.signed.sign(&pub_key, "sid", &value_mem, &signed_buf, .{});
    var sealed_buf: [500]u8 = undefined;
    const sealed_v = try secure.private.seal(&pub_key, "sid", &value_mem, @splat(0x5a), &sealed_buf);

    if (taint) {
        std.valgrind.memcheck.makeMemUndefined(&master_mem);
        std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&pub_key));
        if (target == .seal) std.valgrind.memcheck.makeMemUndefined(&value_mem);
    }
    const master = reload(48, &master_mem);
    var keys = [_]secure.Key{undefined};
    @memcpy(std.mem.asBytes(&keys[0]), &reload(64, std.mem.asBytes(&pub_key)));
    const value = reload(300, &value_mem);

    switch (target) {
        .derive => {
            var k: secure.Key = undefined;
            try secure.Key.deriveInto(&k, &master);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&k)});
        },
        .sign => {
            var out: [400]u8 = undefined;
            const s = try secure.signed.sign(&keys[0], "sid", &value, &out, .{});
            std.debug.print("ctgrind_result={x}\n", .{s[0..secure.signed.tag_b64_len]});
        },
        .verify => {
            var r = secure.signed.verify(&keys, "sid", signed_v, .{});
            // Propagation witness: the verdict, printed while still tainted.
            std.debug.print("ctgrind_verdict={}\n", .{r != null});
            std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&r));
            if (r == null) return error.GenuineRefused;
            std.debug.print("ctgrind_result={x}\n", .{r.?[0..8]});
            var bad: [400]u8 = undefined;
            @memcpy(bad[0..signed_v.len], signed_v);
            bad[signed_v.len - 1] ^= 1;
            var r2 = secure.signed.verify(&keys, "sid", bad[0..signed_v.len], .{});
            std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&r2));
            if (r2 != null) return error.ForgeryAccepted;
        },
        .seal => {
            var out: [500]u8 = undefined;
            const s = try secure.private.seal(&keys[0], "sid", &value, @splat(0x5a), &out);
            std.debug.print("ctgrind_result={x}\n", .{s[0..32]});
        },
        .open => {
            var plain: [500]u8 = undefined;
            var r = secure.private.open(&keys, "sid", sealed_v, &plain);
            std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&r));
            if (r == null) return error.GenuineRefused;
            std.debug.print("ctgrind_result={x}\n", .{r.?[0..8]});
            var bad: [500]u8 = undefined;
            @memcpy(bad[0..sealed_v.len], sealed_v);
            bad[10] = if (bad[10] == 'A') 'B' else 'A';
            var r2 = secure.private.open(&keys, "sid", bad[0..sealed_v.len], &plain);
            std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&r2));
            if (r2 != null) return error.ForgeryAccepted;
        },
    }
}
