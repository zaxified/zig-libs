// SPDX-License-Identifier: MIT

//! ctgrind_harness — the measurement behind `SPEC.md`'s "Constant-time
//! contract". Run it through `../../../scripts/checks/ctgrind.sh aesgcm`,
//! which builds it with and without `-fvalgrind`, runs every target tainted
//! and untainted, and prints the control table.
//!
//! ## What is tainted
//!
//! The KEY and the PLAINTEXT, both marked `MAKE_MEM_UNDEFINED` before the
//! context is built. Everything derived from them — round keys, H and its
//! powers, keystream, ciphertext, `E(K, J0)`, the tag — is then undefined to
//! memcheck, so any branch or address computed from any of it is a context.
//! Nonce, AD and lengths stay defined: they are public by the AEAD's contract.
//!
//! ## What the honest count is
//!
//! Not zero. `open` ends in `if (!timing_safe.eql(computed, tag)) return
//! error.AuthenticationFailed`, and `computed` is key-derived: that branch IS
//! the pass/fail bit the API returns, so it is one context per `open` code
//! path. The comparison producing it is `timing_safe.eql`, branch-free. Every
//! other in-file context would be a leak. `seal` has no reason to branch on
//! anything tainted, so it contributes nothing in-file.
//!
//! ## Targets
//!
//! - `ctx`       — `Context` on the `.aesni` backend (the stitched kernel);
//! - `stateless` — `Aes128Gcm/Aes256Gcm.encrypt/decrypt(…, key)`, which build a
//!                 stack context with only the powers the lengths need;
//! - `generic`   — `Context` on the `.generic` backend (std's AES, CTR and
//!                 GHASH with the schedule cached). Its pattern names std's
//!                 files too: std's property IS this backend's property.
//!
//! Each target runs AES-128 and AES-256 over lengths that reach every path:
//! the short single-group path (0, 13, 64, 96), the tail after AD hashed
//! separately (112 with 20-byte AD), one batch plus the delayed GHASH (200),
//! and the stitched loop with a partial block (1000, 4099) — sealing, opening
//! the genuine record, and opening it with a flipped tag bit.
//!
//! `ctx` and `stateless` need a CPU with AES-NI + PCLMULQDQ; on one without,
//! they exit with an error rather than silently measuring the generic path.
//!
//! ## The traps (as in every harness here)
//!
//! 1. Without `-fvalgrind`, `makeMemUndefined` compiles to nothing and every
//!    row reads 0; the driver builds both ways.
//! 2. `reload` forces a real load from the freshly tainted memory, so the code
//!    under test cannot be handed a defined register copy.
//! 3. ReleaseFast only (the driver's default): ReleaseSafe's checks over
//!    secret-derived data would bury the signal.
//!
//! ## Propagation witness
//!
//! Every tag is printed as hex through `std.debug.print`, which branches on
//! the value: a non-zero witness count beside an in-file count proves the
//! taint reached the output.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const Target = enum { ctx, stateless, generic };

fn reload(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const cases = [_]struct { ad: usize, m: usize }{
    .{ .ad = 0, .m = 0 },
    .{ .ad = 5, .m = 13 },
    .{ .ad = 13, .m = 64 },
    .{ .ad = 5, .m = 96 },
    .{ .ad = 20, .m = 112 },
    .{ .ad = 13, .m = 200 },
    .{ .ad = 13, .m = 1000 },
    .{ .ad = 130, .m = 4099 },
};

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next();
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = std.meta.stringToEnum(Target, target_arg) orelse return error.UnknownTarget;
    const taint = if (std.mem.eql(u8, taint_arg, "yes")) true else if (std.mem.eql(u8, taint_arg, "no")) false else return error.UnknownTaint;
    if (target != .generic and !root.available(.aesni)) return error.NoAesNi;

    std.debug.print("valgrind_support={} target={t} backend={t}\n", .{ builtin.valgrind_support, target, root.backend() });

    inline for (.{ root.Aes128Gcm, root.Aes256Gcm }) |Gcm| {
        var wide: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("ctgrind-aesgcm-harness-key-v1", &wide, .{});
        var key_mem: [Gcm.key_length]u8 = wide[0..Gcm.key_length].*;
        var pt_mem: [4099]u8 = undefined;
        for (&pt_mem, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
        if (taint) {
            std.valgrind.memcheck.makeMemUndefined(&key_mem);
            std.valgrind.memcheck.makeMemUndefined(&pt_mem);
        }
        const key = reload(Gcm.key_length, &key_mem);

        var ad: [130]u8 = undefined;
        for (&ad, 0..) |*b, i| b.* = @truncate(i *% 13 +% 1);
        const nonce: [12]u8 = .{ 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };

        var ctx = switch (target) {
            .ctx, .stateless => Gcm.initWith(.aesni, key).?,
            .generic => Gcm.initWith(.generic, key).?,
        };
        defer ctx.wipe();

        for (cases) |cs| {
            const m = reload(4099, &pt_mem);
            var c: [4099]u8 = undefined;
            var back: [4099]u8 = undefined;
            var tag: [16]u8 = undefined;
            const a = ad[0..cs.ad];
            switch (target) {
                .ctx, .generic => ctx.encrypt(c[0..cs.m], &tag, m[0..cs.m], a, nonce),
                .stateless => Gcm.encrypt(c[0..cs.m], &tag, m[0..cs.m], a, nonce, key),
            }
            // Propagation witness: hex formatting branches on the tag.
            std.debug.print("seal{d}[{d}/{d}]\n", .{ Gcm.key_length * 8, cs.ad, cs.m });
            std.debug.print("ctgrind_result={x}\n", .{tag});

            const ok = switch (target) {
                .ctx, .generic => ctx.decrypt(back[0..cs.m], c[0..cs.m], tag, a, nonce),
                .stateless => Gcm.decrypt(back[0..cs.m], c[0..cs.m], tag, a, nonce, key),
            };
            ok catch |e| return e;

            var bad = tag;
            bad[15] ^= 0x80;
            const rejected = switch (target) {
                .ctx, .generic => ctx.decrypt(back[0..cs.m], c[0..cs.m], bad, a, nonce),
                .stateless => Gcm.decrypt(back[0..cs.m], c[0..cs.m], bad, a, nonce, key),
            };
            if (rejected) |_| return error.ForgeryAccepted else |_| {}
        }
    }
}
