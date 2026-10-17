// SPDX-License-Identifier: MIT

//! ctgrind_harness — the measurement behind `SPEC.md`'s constant-time line.
//! Run it through `../../../scripts/checks/ctgrind.sh aaa-gate`, which builds
//! it with and without `-fvalgrind`, runs every target tainted and
//! untainted, and prints the control table.
//!
//! ## What is secret, what is public
//!
//! The SECRET is what the gate holds: the SHA-256 fingerprints of the
//! configured bearer tokens, API keys and Basic `user:password` pairs. They
//! are tainted in place, in the gate's own lists, after `init`. The presented
//! credential is the client's own bytes (public to the attacker by
//! definition), and the accept/reject verdict is public by design — a client
//! learns it from the status code.
//!
//! ## What the honest count is
//!
//! Each target calls the verifier twice, with a configured credential and
//! with one that is not, and declassifies each verdict before the harness's
//! own branch on it. The module's in-file contexts are then exactly the
//! verdict: the `if` on the result of the digest scan inside `verify*`
//! (`containsFp` itself folds every comparison into one bool without an
//! early exit). Itemised in `SPEC.md`; pinned in `ctgrind-expected.tsv`.
//!
//! No propagation witness can fire: the verdict leaves the module as a
//! constant enum picked by that one branch, so the in-file count IS the
//! proof the taint arrived, and the output pin (`ctgrind_result=`) proves
//! the gate ran. ReleaseFast only (the driver's default).

const std = @import("std");
const builtin = @import("builtin");
const aaa = @import("root.zig");

const Target = enum { bearer, api_key, basic };

const tokens = [_][]const u8{ "tok-alpha-0123456789abcdef", "tok-bravo-0123456789abcdef", "tok-charlie-0123456789abcd" };

fn taintList(list: anytype) void {
    std.valgrind.memcheck.makeMemUndefined(std.mem.sliceAsBytes(list));
}

fn declassify(v: *aaa.Gate.Verdict) void {
    std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(v));
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next();
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = std.meta.stringToEnum(Target, target_arg) orelse return error.UnknownTarget;
    const taint = if (std.mem.eql(u8, taint_arg, "yes")) true else if (std.mem.eql(u8, taint_arg, "no")) false else return error.UnknownTaint;
    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    const gpa = std.heap.page_allocator; // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
    var g = try aaa.Gate.init(gpa, .{
        .token = tokens[0],
        .extra_tokens = tokens[1..],
        .api_key = tokens[0],
        .extra_api_keys = tokens[1..],
        .basic_users = &.{
            .{ .user = "user-0", .password = tokens[0] },
            .{ .user = "user-1", .password = tokens[1] },
            .{ .user = "user-2", .password = tokens[2] },
        },
    });
    defer g.deinit();
    if (taint) {
        taintList(g.tokens.items);
        taintList(g.api_keys.items);
        taintList(g.basics.items);
    }

    var good: aaa.Gate.Verdict = undefined;
    var bad: aaa.Gate.Verdict = undefined;
    switch (target) {
        .bearer => {
            good = g.verify(tokens[1]);
            bad = g.verify("tok-wrong-00000000000000000");
        },
        .api_key => {
            good = g.verifyApiKey(tokens[2]);
            bad = g.verifyApiKey("tok-wrong-00000000000000000");
        },
        .basic => {
            good = g.verifyBasic(.{ .user = "user-1", .password = tokens[1] });
            bad = g.verifyBasic(.{ .user = "user-1", .password = tokens[2] });
        },
    }
    declassify(&good);
    declassify(&bad);
    if (good == .denied) return error.GenuineRefused;
    if (bad != .denied) return error.ForgeryAccepted;
    // Output pin: the two verdicts and the set sizes, as hex (the driver
    // pins `ctgrind_result=<hex>`; a harness that never reached the gate
    // could not print these values).
    const pin: u32 = (@as(u32, @intFromEnum(good)) << 24) | (@as(u32, @intFromEnum(bad)) << 16) |
        (@as(u32, @intCast(g.tokenCount())) << 8) | @as(u32, @intCast(g.basicCount()));
    std.debug.print("ctgrind_result={x:0>8}\n", .{pin});
}
