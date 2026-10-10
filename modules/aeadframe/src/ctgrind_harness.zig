// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh aeadframe`, which
//! builds every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-aeadframe`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `chacha` / `aes` — the channel key and the plaintext tainted:
//!    `Sealer.seal` of three records, `rekeyInto` to a second tainted key,
//!    one more record; the `Opener` opens all four (records marked defined
//!    first: they are the wire), and rejects a copy with one tag bit flipped.
//!    Header, sequence numbers, epochs and lengths are public.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const af = @import("root.zig");

const Target = enum { chacha, aes };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn run(comptime C: type, t: Taint) !void {
    var k1 = secretBytes(32, "ctgrind-aeadframe-key1-v1");
    var k2 = secretBytes(32, "ctgrind-aeadframe-key2-v1");
    var pt = secretBytes(32, "ctgrind-aeadframe-plaintext-v1");
    if (t == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&k1);
        std.valgrind.memcheck.makeMemUndefined(&k2);
        std.valgrind.memcheck.makeMemUndefined(&pt);
    }
    var sealer: C.Sealer = undefined;
    C.Sealer.initInto(&sealer, &k1, 1);
    var opener: C.Opener = undefined;
    C.Opener.initInto(&opener, &k1, 1);

    var recs: [4][128]u8 = undefined;
    var lens: [4]usize = undefined;
    for (0..4) |i| {
        if (i == 3) try sealer.rekeyInto(&k2, 2);
        lens[i] = try sealer.seal(&recs[i], &pt, "aad");
        std.valgrind.memcheck.makeMemDefined(recs[i][0..lens[i]]);
    }
    var out: [64]u8 = undefined;
    for (0..4) |i| {
        if (i == 3) opener.rekeyInto(&k2, 2);
        const n = try opener.open(&out, recs[i][0..lens[i]], "aad");
        std.debug.print("ctgrind_result={x}\n", .{out[0..n]});
    }
    var bad = recs[3];
    bad[lens[3] - 1] ^= 0x01;
    const rejected = if (opener.open(&out, bad[0..lens[3]], "aad")) |_| false else |_| true;
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
        .chacha => try run(af.ChaChaChannel, taint),
        .aes => try run(af.AesGcmChannel, taint),
    }
}
