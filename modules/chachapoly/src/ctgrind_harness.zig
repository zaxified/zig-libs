// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant
//! time" section and for `poly1305.zig`'s own doc-comment table, as an actual
//! committed program instead of numbers a reader has to take on faith. Run it
//! through `../../../scripts/ctgrind.sh chachapoly`, which builds every
//! mode/switch/taint combination and prints the control table.
//!
//! Until 2026-08-11 both tables existed WITHOUT this file: the measurement had
//! been made once, by hand, and then only its result was written down. That is
//! the shape this repo now treats as a finding — a ctgrind claim nobody can
//! re-run is indistinguishable from one that was never made.
//!
//! This file is deliberately NOT wired into `zig build test-chachapoly`:
//! memcheck's context count is valgrind's own output, not something a Zig test
//! can observe. `zig build check-ctgrind` (part of `zig build test`) compiles
//! it so it cannot rot into an unbuildable recipe; running it is the driver
//! script's job.
//!
//! ## What this measures
//!
//! The 32-byte Poly1305 key is marked `MAKE_MEM_UNDEFINED` and driven through
//! `Poly1305.create` at 16 / 64 / 192 / 1024 / 8192 B — the sizes that hit the
//! one-block path, the sub-group tail, an exact `wide` group, and several full
//! groups — plus a chunked `update`/`pad`/`update`/`final` stream, which is
//! the only path that exercises the leftover buffer across a `pad`.
//!
//! ## Why the mode column is the whole point
//!
//! The lane-parallel MAC uses CHECKED `*` / `+` rather than `*%` / `+%` on
//! purpose (a deferred-carry bounds mistake should panic, not silently forge a
//! tag). In `Debug`/`ReleaseSafe` the compiler turns each of those into an
//! overflow branch on a secret-derived value, so the constant-time claim holds
//! at `ReleaseFast` and measurably NOT below it. Those non-zero rows are not
//! noise to be explained away — they are this harness's built-in positive
//! control: they prove the taint reaches `poly1305.zig`'s arithmetic, which is
//! exactly what the `ReleaseFast` zero would otherwise be unable to establish.
//!
//! ## The two traps
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, and the release
//!    optimize modes default that off. Built WITHOUT `-fvalgrind` every client
//!    request compiles to nothing and `taint=yes` silently behaves like
//!    `taint=no` — a clean run that measured nothing. The driver builds both
//!    ways so this is a row, not an assumption.
//! 2. An optimizer may keep a defined register copy of the key from before
//!    `makeMemUndefined` ran, so the MAC would never read the memory that was
//!    marked. `reloadVolatile` forces one real load from freshly-tainted
//!    memory immediately before the call under test. As in `ct25519`'s
//!    harness this is DEFENSIVE, not demonstrated: it is insurance against a
//!    codegen change.
//!
//! ## The propagation witness
//!
//! Every tag is formatted through `std.debug.print`, which is not
//! constant-time (hex formatting branches on the value). At `ReleaseFast` the
//! total count is therefore non-zero while the `poly1305.zig` count is zero —
//! that is what makes the zero mean "no branch found in the MAC" rather than
//! "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const poly1305 = @import("poly1305.zig");

const Poly1305 = poly1305.Poly1305;

/// Deterministic "random" key. Computed at runtime (not folded at comptime) so
/// tainting it actually marks the memory the MAC reads. Not a KAT — a fixed
/// seed only keeps repeated runs of the table comparable.
fn secretKey() [32]u8 {
    var k: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ctgrind-chachapoly-harness-secret-key-v1", &k, .{});
    return k;
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the MAC cannot be fed a copy that predates `makeMemUndefined`.
fn reloadVolatile(s: *const [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

/// Message lengths chosen to cover every structural path of the lane-parallel
/// MAC at `lanes = 4`: below one block, one full block plus remainder, exactly
/// one wide group (192 B = 4 x 16 x 3), several groups, and a large buffer.
const sizes = [_]usize{ 16, 64, 192, 1024, 8192 };

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    if (!std.mem.eql(u8, target_arg, "poly1305")) return error.UnknownTarget;
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} lanes={d}\n", .{ builtin.valgrind_support, poly1305.lanes });

    var key = secretKey();
    if (taint == .yes) {
        std.valgrind.memcheck.makeMemUndefined(&key);
    }
    const secret = reloadVolatile(&key);

    // Public message bytes: a fixed pattern, never tainted. Any branch the MAC
    // takes on message length or buffer occupancy is legitimate and must NOT
    // show up as a context, which is only true if the message stays defined.
    var msg: [8192]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);

    // One-shot: the code under test at each structural size.
    for (sizes) |n| {
        var tag: [16]u8 = undefined;
        Poly1305.create(&tag, msg[0..n], &secret);
        // Propagation witness: hex formatting is not constant-time.
        std.debug.print("create[{d}]={x}\n", .{ n, tag });
    }

    // Streaming: the only path through the leftover buffer across a `pad`.
    {
        var st = Poly1305.init(&secret);
        st.update(msg[0..37]);
        st.pad();
        st.update(msg[37..1000]);
        var tag: [16]u8 = undefined;
        st.final(&tag);
        std.debug.print("stream={x}\n", .{tag});
    }
}
