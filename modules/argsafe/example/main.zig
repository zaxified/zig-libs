// SPDX-License-Identifier: MIT

//! What a consumer building an exec argv from untrusted input does with
//! `argsafe`: run the convenience predicates over the shapes this module
//! exists to reject (shell metacharacters, a leading `-`, an embedded NUL,
//! an empty argument), the same discipline hand-assembled via `CharClass`
//! directly, then assemble a realistic argv end to end with the typed
//! `Argv` builder — including a rejection partway through, proving the
//! builder both poisons (a later `slice()` still fails even once the
//! caller has handled the earlier error) and frees its backing storage on
//! the rejected path, not just the accepted one.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const argsafe = @import("argsafe");

/// A check that survives EVERY optimize mode, unlike a debug-only assert:
/// `-Doptimize=ReleaseFast` compiles those out, and `scripts/test.sh` does not
/// merely BUILD the examples, it RUNS them in the lane's own optimize mode --
/// so in a release lane the check vanished and the example went on printing
/// that it had passed. See `scripts/check-example-assert.py`.
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    // A DebugAllocator that panics on leak makes this example a leak
    // detector for `Argv`'s ownership contract (CONVENTIONS.md §7.2) — in
    // particular that a rejected push still leaves `deinit` able to free
    // everything pushed before it.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── the shapes this module exists to reject, on the convenience predicates ──
    must(!argsafe.isSafeIdentifier("--help"), @src()); // leading '-'
    must(!argsafe.isSafeIdentifier("-rf"), @src());
    must(!argsafe.isSafeIdentifier("a;rm -rf /"), @src()); // shell metachar
    must(!argsafe.isSafeIdentifier("a\x00b"), @src()); // embedded NUL
    must(!argsafe.isSafeIdentifier(""), @src()); // empty argument
    must(!argsafe.isSafePath("../../etc/shadow"), @src()); // traversal, not absolute
    must(!argsafe.isSafePath("/etc/passwd\x00.jpg"), @src()); // NUL smuggling past a "looks safe" prefix
    must(!argsafe.isSafeUrl("http://host/`id`"), @src()); // command-substitution shape
    must(!argsafe.isSafeKvValue("-tcp", false), @src()); // flag injection via a value position
    std.debug.print("convenience predicates: every rejection shape confirmed rejected\n", .{});

    // ── the same discipline, hand-assembled via CharClass directly ──────────
    const iface_class: argsafe.CharClass = .{ .extra = "_-", .max_len = 16, .first_char = .alnum };
    must(iface_class.check("wg0"), @src());
    must(!iface_class.check("; rm -rf /"), @src());
    must(!iface_class.check("-x"), @src());
    must(!iface_class.check(""), @src());
    const iface_pred = iface_class.predicate();
    must(iface_pred("wg0"), @src());
    must(!iface_pred("$(whoami)"), @src());

    // ── a realistic argv end to end: `wg set wg0 peer <key> allowed-ips <cidr>` ──
    {
        var argv: argsafe.Argv = .empty;
        defer argv.deinit(gpa);

        try argv.push(gpa, "wg");
        try argv.push(gpa, "set");
        try argv.pushChecked(gpa, "wg0", iface_class);
        try argv.push(gpa, "peer");
        const pubkey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12="; // 44-byte WireGuard key shape
        try argv.pushIf(gpa, pubkey, struct {
            fn f(s: []const u8) bool {
                return argsafe.isSafeBase64(s, 44);
            }
        }.f);
        try argv.push(gpa, "allowed-ips");
        try argv.pushIf(gpa, "10.0.0.0/24,fd00::/8", struct {
            fn f(s: []const u8) bool {
                return argsafe.isSafeCidrList(s, ',');
            }
        }.f);

        const got = try argv.slice();
        must(got.len == 7, @src());
        std.debug.print("assembled argv ({d} elements):", .{got.len});
        for (got) |tok| std.debug.print(" {s}", .{tok});
        std.debug.print("\n", .{});
    }

    // ── a rejection partway through: the builder poisons AND its backing
    // storage is still freed on the reject path (proven by the outer
    // DebugAllocator, not just printed here) ────────────────────────────────
    {
        var argv: argsafe.Argv = .empty;
        defer argv.deinit(gpa);

        try argv.push(gpa, "date");
        try argv.push(gpa, "-s");
        // Attacker-controlled spec value carrying a shell metacharacter.
        const spec_class: argsafe.CharClass = .{ .extra = ": -.@+TZ", .first_char = .alnum };
        const push_res = argv.pushChecked(gpa, "2020;reboot", spec_class);
        if (push_res) |_| {
            unreachable;
        } else |err| switch (err) {
            error.Rejected => std.debug.print("date -s spec with a shell metachar: Rejected (expected)\n", .{}),
            else => return err,
        }
        // Poisoned even though the caller already handled the error above —
        // slice() must fail too, so a validation failure can never silently
        // ship a short argv.
        const sliced = argv.slice();
        if (sliced) |_| {
            unreachable;
        } else |err| switch (err) {
            error.Rejected => std.debug.print("builder stays poisoned: slice() also Rejected (expected)\n", .{}),
        }
    }

    // ── isInAllowlist: exact membership only, no partial/metachar match ────
    const levels = &.{ "err", "warn", "info", "debug" };
    must(argsafe.isInAllowlist("info", levels), @src());
    must(!argsafe.isInAllowlist("info; rm -rf /", levels), @src());
    std.debug.print("isInAllowlist: exact membership only\n", .{});
}
