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
//!    `std.crypto.core.modes.ctr` over the context and the context's own
//!    `ctr`.
//!  * `dec` — the key and four ciphertext blocks tainted: `initDec`,
//!    `initDecInto`, `initFromEnc` (the InvMixColumns of the schedule),
//!    `decrypt` and `decryptWide(4)`.
//!  * `bitsliced` — the key and one full batch of plaintext tainted: the
//!    round keys packed (`bitsliced.zig` `Wide.packKeys`, what the contexts
//!    do at `init` without AES hardware), then `Wide.encrypt(12, …)` and
//!    `Wide.decrypt(12, …)` over the batch — the rounds every context call
//!    runs on the software backend (`root.zig` `bitslicedBlocks` adds only
//!    two `@memcpy`s around them).
//!
//! Which backend `enc`/`dec` measure is the build's CPU: `ctgrind.sh` pins
//! `-Dcpu=skylake` (AES-NI). The bitsliced core is plain integer code, so the
//! `bitsliced` row measures it on that same pinned CPU; that is why it is a
//! target of its own rather than an `enc`/`dec` run under
//! `CTGRIND_CPU=x86_64`, where the key expansion (std's masked S-box
//! through `subWord`, level with std's own soft `expandKey`) adds loads the
//! rounds no longer have (SPEC.md, *Constant-time contract*).
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const aes192 = @import("root.zig");
const bitsliced = @import("bitsliced.zig");

const Target = enum { enc, dec, bitsliced };
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
    ctx.ctr(&out, &pt, iv);
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

fn runBitsliced(t: Taint) void {
    var key = secretBytes(24, "ctgrind-aes192-key-v1");
    var data: [bitsliced.width * 16]u8 = undefined;
    for (0..bitsliced.width) |i| {
        var label = "ctgrind-aes192-bs-v1-00".*;
        label[label.len - 2] = '0' + @as(u8, @intCast(i / 10));
        label[label.len - 1] = '0' + @as(u8, @intCast(i % 10));
        data[i * 16 ..][0..16].* = secretBytes(16, &label);
    }
    if (t == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&key);
        std.valgrind.memcheck.makeMemUndefined(&data);
    }
    const ctx = aes192.Aes192.initEnc(key);
    const keys = bitsliced.Wide.packKeys(ctx.key_schedule.round_keys[0..]);
    bitsliced.Wide.encrypt(aes192.rounds, &keys, &data);
    print(&data);
    bitsliced.Wide.decrypt(aes192.rounds, &keys, &data);
    print(&data);
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
        .bitsliced => runBitsliced(taint),
    }
}
