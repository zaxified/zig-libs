// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh aeskw`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-aeskw`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `wrap` — the KEK and the key being wrapped tainted, AES-128, AES-192
//!    (the `aes192` module) and AES-256 KEKs: `wrap`, `unwrap` of the result, and `unwrap` of a copy with one
//!    ciphertext byte flipped (rejected on the integrity check, which must be
//!    a constant-time compare folded into one verdict). The wrapped output is
//!    public (it is what goes on the wire) and is marked defined before the
//!    tampered copy is made, so the flip is not on a secret.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const aeskw = @import("root.zig");

const Target = enum { wrap };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn run(comptime kek_len: usize, t: Taint) !void {
    var kek = secretBytes(kek_len, "ctgrind-aeskw-kek-v1");
    var key = secretBytes(32, "ctgrind-aeskw-key-v1");
    if (t == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&kek);
        std.valgrind.memcheck.makeMemUndefined(&key);
    }
    var wrapped_buf: [40]u8 = undefined;
    const wrapped = try aeskw.wrap(&kek, &key, &wrapped_buf);
    std.debug.print("ctgrind_result={x}\n", .{wrapped});
    std.valgrind.memcheck.makeMemDefined(wrapped);

    var back: [32]u8 = undefined;
    const got = try aeskw.unwrap(&kek, wrapped, &back);
    std.debug.print("ctgrind_result={x}\n", .{got});

    var bad = wrapped_buf;
    bad[17] ^= 0x01;
    const rejected = if (aeskw.unwrap(&kek, &bad, &back)) |_| false else |_| true;
    std.debug.print("ctgrind_result={x}\n", .{[1]u8{@intFromBool(rejected)}});
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
        .wrap => {
            try run(16, taint);
            try run(24, taint);
            try run(32, taint);
        },
    }
}
