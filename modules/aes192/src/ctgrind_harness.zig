// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening
//! line. Run it through `../../../scripts/checks/ctgrind.sh aes192`, which
//! builds every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-aes192`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `enc` — the key and four plaintext blocks tainted: `initEnc`,
//!    `initEncInto` (the key expansion, i.e. `subWord` through std's
//!    `encryptLast`), `encrypt`, `encryptWide(4)`, `xor`, `xorWide(4)` and
//!    `std.crypto.core.modes.ctr` over the context.
//!  * `dec` — the key and four ciphertext blocks tainted: `initDec`,
//!    `initDecInto`, `initFromEnc` (the InvMixColumns of the schedule),
//!    `decrypt` and `decryptWide(4)`.
//!
//! Which backend is measured is the build's CPU: `ctgrind.sh` pins
//! `-Dcpu=skylake` (AES-NI). `CTGRIND_CPU=x86_64 scripts/checks/ctgrind.sh
//! aes192` measures std's software path instead (SPEC.md records the result;
//! not a pinned row, because the script pins one CPU for every module).
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const aes192 = @import("root.zig");

const Target = enum { enc, dec };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(label, &full, .{});
    return full[0..n].*;
}

fn print(bytes: []const u8) void {
    std.debug.print("ctgrind_result={x}\n", .{bytes});
}

fn runEnc(t: Taint) void {
    var key = secretBytes(24, "ctgrind-aes192-key-v1");
    var pt = secretBytes(64, "ctgrind-aes192-pt-v1");
    const iv = secretBytes(16, "ctgrind-aes192-iv-v1"); // public
    if (t == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&key);
        std.valgrind.memcheck.makeMemUndefined(&pt);
    }
    const ctx = aes192.Aes192.initEnc(key);
    var ctx2: aes192.Aes192EncryptCtx = undefined;
    aes192.Aes192.initEncInto(&ctx2, &key);

    var out: [64]u8 = undefined;
    ctx.encrypt(out[0..16], pt[0..16]);
    print(out[0..16]);
    ctx2.encryptWide(4, &out, &pt);
    print(&out);
    ctx.xor(out[0..16], pt[0..16], iv);
    print(out[0..16]);
    var ctrs: [64]u8 = undefined;
    for (0..4) |i| ctrs[i * 16 ..][0..16].* = iv;
    ctx.xorWide(4, &out, &pt, ctrs);
    print(&out);
    std.crypto.core.modes.ctr(aes192.Aes192EncryptCtx, ctx, &out, &pt, iv, .big);
    print(&out);
}

fn runDec(t: Taint) void {
    var key = secretBytes(24, "ctgrind-aes192-key-v1");
    var ct = secretBytes(64, "ctgrind-aes192-ct-v1");
    if (t == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&key);
        std.valgrind.memcheck.makeMemUndefined(&ct);
    }
    const ctx = aes192.Aes192.initDec(key);
    var ctx2: aes192.Aes192DecryptCtx = undefined;
    aes192.Aes192.initDecInto(&ctx2, &key);
    const ctx3 = aes192.Aes192DecryptCtx.initFromEnc(aes192.Aes192.initEnc(key));

    var out: [64]u8 = undefined;
    ctx.decrypt(out[0..16], ct[0..16]);
    print(out[0..16]);
    ctx2.decryptWide(4, &out, &ct);
    print(&out);
    ctx3.decryptWide(4, &out, &ct);
    print(&out);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t} hw={}\n", .{ builtin.valgrind_support, target, aes192.has_hardware_support });
    switch (target) {
        .enc => runEnc(taint),
        .dec => runDec(taint),
    }
}
