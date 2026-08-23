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

pub fn main() !void {
    // A DebugAllocator that panics on leak makes this example a leak
    // detector for `Argv`'s ownership contract (CONVENTIONS.md §7.2) — in
    // particular that a rejected push still leaves `deinit` able to free
    // everything pushed before it.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── the shapes this module exists to reject, on the convenience predicates ──
    std.debug.assert(!argsafe.isSafeIdentifier("--help")); // leading '-'
    std.debug.assert(!argsafe.isSafeIdentifier("-rf"));
    std.debug.assert(!argsafe.isSafeIdentifier("a;rm -rf /")); // shell metachar
    std.debug.assert(!argsafe.isSafeIdentifier("a\x00b")); // embedded NUL
    std.debug.assert(!argsafe.isSafeIdentifier("")); // empty argument
    std.debug.assert(!argsafe.isSafePath("../../etc/shadow")); // traversal, not absolute
    std.debug.assert(!argsafe.isSafePath("/etc/passwd\x00.jpg")); // NUL smuggling past a "looks safe" prefix
    std.debug.assert(!argsafe.isSafeUrl("http://host/`id`")); // command-substitution shape
    std.debug.assert(!argsafe.isSafeKvValue("-tcp", false)); // flag injection via a value position
    std.debug.print("convenience predicates: every rejection shape confirmed rejected\n", .{});

    // ── the same discipline, hand-assembled via CharClass directly ──────────
    const iface_class: argsafe.CharClass = .{ .extra = "_-", .max_len = 16, .first_char = .alnum };
    std.debug.assert(iface_class.check("wg0"));
    std.debug.assert(!iface_class.check("; rm -rf /"));
    std.debug.assert(!iface_class.check("-x"));
    std.debug.assert(!iface_class.check(""));
    const iface_pred = iface_class.predicate();
    std.debug.assert(iface_pred("wg0"));
    std.debug.assert(!iface_pred("$(whoami)"));

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
        std.debug.assert(got.len == 7);
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
    std.debug.assert(argsafe.isInAllowlist("info", levels));
    std.debug.assert(!argsafe.isInAllowlist("info; rm -rf /", levels));
    std.debug.print("isInAllowlist: exact membership only\n", .{});
}
