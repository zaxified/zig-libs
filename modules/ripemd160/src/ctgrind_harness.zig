// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh ripemd160`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-ripemd160`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! RIPEMD-160 is unkeyed, so the secret is the MESSAGE: a hashed preimage or a
//! key fed through `hash160` is the case where a data-dependent branch or table
//! index inside `compress` would leak. The message is marked
//! `MAKE_MEM_UNDEFINED` and hashed one-shot at 0 / 1 / 55 / 56 / 64 / 1000 B
//! (empty, one byte, the last length whose padding fits one block, the first
//! that needs a second, an exact block, many blocks with a tail) and through a
//! chunked `update` stream that crosses the partial buffer. The lengths are
//! public and stay defined: branches on them are legitimate.
//!
//! `hash160` is the second target: std's SHA-256 followed by this module's
//! compression, i.e. the composite the Bitcoin modules actually call.
//!
//! ## The propagation witness
//!
//! Every digest is printed through `std.debug.print`, whose hex formatting is
//! not constant-time. The total count is therefore non-zero while the
//! `root.zig` count is zero — that is what makes the zero mean "no branch in
//! the hash" rather than "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const Ripemd160 = root.Ripemd160;

const Taint = enum { yes, no };
const Target = enum { hash, hash160 };

const sizes = [_]usize{ 0, 1, 55, 56, 64, 1000 };

/// Deterministic "secret" message, computed at runtime so tainting it marks
/// the memory the hash reads. Not a KAT.
fn secretMessage(buf: []u8) void {
    var prng = std.Random.DefaultPrng.init(0x5249_5045_4d44_3136);
    prng.random().bytes(buf);
}

/// Forces one real load from `s` through a volatile pointer, so the hash
/// cannot be fed a register copy that predates `makeMemUndefined`.
fn reloadVolatile(dst: []u8, s: []const u8) void {
    for (dst, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var raw: [1000]u8 = undefined;
    secretMessage(&raw);
    if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
    var msg: [1000]u8 = undefined;
    reloadVolatile(&msg, &raw);

    switch (target) {
        .hash => {
            for (sizes) |n| {
                var out: [Ripemd160.digest_length]u8 = undefined;
                Ripemd160.hash(msg[0..n], &out, .{});
                // Propagation witness: hex formatting is not constant-time.
                std.debug.print("hash[{d}]={x}\n", .{ n, out });
            }
            // Streaming across the partial buffer: 37 + 90 + 873.
            var d = Ripemd160.init(.{});
            d.update(msg[0..37]);
            d.update(msg[37..127]);
            d.update(msg[127..]);
            var out: [Ripemd160.digest_length]u8 = undefined;
            d.final(&out);
            std.debug.print("stream={x}\n", .{out});
        },
        .hash160 => {
            for ([_]usize{ 33, 1000 }) |n| {
                var out: [Ripemd160.digest_length]u8 = undefined;
                root.hash160(msg[0..n], &out);
                std.debug.print("hash160[{d}]={x}\n", .{ n, out });
            }
        },
    }
}
