// SPDX-License-Identifier: MIT

//! ctgrind_harness — `btcaddr`'s entry in the constant-time gate. Run it
//! through `../../../scripts/checks/ctgrind.sh btcaddr`.
//!
//! NOT wired into `zig build test-btcaddr` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## Target — taints ONE secret and nothing that is public
//!
//! * `wif` — a private key through `wifEncode` and back through `wifDecode`
//!   (added 2026-10-18). Covers what `bip32/xprv` does not: the borrow-and-
//!   mask `keyInRange` on both sides (it replaced an early-exit `mem.eql` +
//!   `mem.order`) and the declassified version byte / compression flag. The
//!   Base58Check text is the key in another radix, so the string stays
//!   tainted end to end; the network and the compression flag are public
//!   arguments and are not tainted.
//!
//! ## Verdicts are declassified, payloads are not
//!
//! `settle` reads the payload without a branch, checks the error tag on a
//! DECLASSIFIED copy (accept or reject is what any caller learns anyway), and
//! returns the still-tainted payload, printed as the propagation witness.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind` every row reads 0 regardless — the driver prints
//!    that as its own row.
//! 2. `reloadVolatile` forces a real load from freshly tainted memory, so a
//!    constant-folded copy of the fixed key cannot be used instead.
//! 3. ReleaseFast only.

const std = @import("std");
const builtin = @import("builtin");
const btcaddr = @import("root.zig");
const memcheck = std.valgrind.memcheck;

const Target = enum { wif };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    inline for (@typeInfo(Target).@"enum".fields) |f| {
        if (std.mem.eql(u8, s, f.name)) return @field(Target, f.name);
    }
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn reloadVolatile(comptime T: type, s: *const T) T {
    const v: *const volatile T = s;
    return v.*;
}

fn taintBytes(buf: []u8, out: []u8, taint: Taint) void {
    if (taint == .yes) memcheck.makeMemUndefined(buf);
    for (buf, out) |*b, *o| o.* = reloadVolatile(u8, b);
}

fn settle(r: anytype) !@typeInfo(@TypeOf(r)).error_union.payload {
    const payload = r catch undefined;
    var copy = r;
    memcheck.makeMemDefined(std.mem.asBytes(&copy));
    _ = try reloadVolatile(@TypeOf(r), &copy);
    return payload;
}

fn decodeValue(s: []const u8) btcaddr.WifDecodeError!btcaddr.Wif {
    var w: btcaddr.Wif = undefined;
    try btcaddr.wifDecode(&w, s);
    return w;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const taint = try parseTaint(it.next() orelse return error.MissingTaint);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .wif => {
            var raw: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("ctgrind-btcaddr-harness-key-v1", &raw, .{});
            var key: [32]u8 = undefined;
            taintBytes(&raw, &key, taint);
            var text_buf: [btcaddr.max_wif_len]u8 = undefined;
            const text = try settle(btcaddr.wifEncode(&key, true, .mainnet, &text_buf));
            var w = try settle(decodeValue(text));
            defer w.wipe();
            std.debug.print("key={x}\n", .{w.key});
        },
    }
}
