// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh aesccm`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-aesccm`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `aead` — the key and the plaintext tainted, AES-128 and AES-256, tags
//!    8 and 16, 12-byte nonce: `seal`, `open` of the result, and `open` of a
//!    copy with one ciphertext byte flipped (rejected on the tag check, which
//!    must be one constant-time verdict). The sealed output is public (it
//!    goes on the wire) and is marked defined before the tampered copy is
//!    made, so the flip is not on a secret.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is the verdicts only.

const std = @import("std");
const builtin = @import("builtin");
const aesccm = @import("root.zig");

const Target = enum { aead };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn run(comptime C: type, t: Taint) !void {
    var key = secretBytes(C.key_length, "ctgrind-aesccm-key-v1");
    var pt = secretBytes(29, "ctgrind-aesccm-pt-v1");
    if (t == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&key);
        std.valgrind.memcheck.makeMemUndefined(&pt);
    }
    const nonce: [C.nonce_length]u8 = @splat(0x42);
    var s = C.init(key);
    defer s.deinit();
    var c: [pt.len]u8 = undefined;
    var tag: [C.tag_length]u8 = undefined;
    try s.seal(&c, &tag, &pt, "header", nonce);
    std.valgrind.memcheck.makeMemDefined(&c);
    std.valgrind.memcheck.makeMemDefined(&tag);
    std.debug.print("ctgrind_result={x}{x}\n", .{ c, tag });

    var back: [pt.len]u8 = undefined;
    try s.open(&back, &c, tag, "header", nonce);
    std.debug.print("ctgrind_result={x}\n", .{back});

    var bad = c;
    bad[3] ^= 0x01;
    const rejected = if (s.open(&back, &bad, tag, "header", nonce)) |_| false else |_| true;
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
        .aead => {
            try run(aesccm.Aes128Ccm8, taint);
            try run(aesccm.Aes128Ccm, taint);
            try run(aesccm.Aes256Ccm8, taint);
            try run(aesccm.Aes256Ccm, taint);
        },
    }
}
