// SPDX-License-Identifier: MIT

//! What a firewall-provisioning consumer does with `nftables`: describe the
//! table/chain/rule it wants, hand it to a `Batch`, and get back the exact
//! bytes a `sendmsg(2)` to `NETLINK_NETFILTER` would carry — no socket
//! opened here, since an example has no business touching kernel state.
//!
//! Built against the PUBLISHED module (`@import("nftables")`) only: no
//! `test_deps`, no access to the module's private `goldens.zig` or
//! `socket.zig`. If a type this file needs were not exported, the file would
//! stop compiling — that is the point of an example.

const std = @import("std");
const nftables = @import("nftables");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // A base chain hooked on `input` with a default-drop policy, plus one
    // rule that opens TCP/22 — the shape every "allow SSH, drop the rest"
    // ruleset starts from.
    var batch = try nftables.Batch.init(gpa, 0, .{});
    defer batch.deinit();

    try batch.addTable(.{ .family = .inet, .name = "filter" });
    try batch.addChain(.{
        .family = .inet,
        .table = "filter",
        .name = "input",
        .chain_type = .filter,
        .hook = .input,
        .prio = 0,
        .policy = .drop,
    });

    var prog = nftables.expr.Program.init(gpa, .inet);
    defer prog.deinit();
    _ = prog.tcpDport(22).accept();
    try batch.addRule(.{
        .family = .inet,
        .table = "filter",
        .chain = "input",
        .exprs = try prog.finish(),
    });

    const wire = try batch.finish();
    std.debug.print("batch: {d} command(s), {d} wire bytes\n", .{ batch.commandCount(), wire.len });

    // Walk the batch back with the same decoders a reply handler would use.
    // This is the seam a consumer without a live kernel can actually
    // exercise: the encode and decode halves agree on what a
    // NEWTABLE/NEWCHAIN/NEWRULE payload looks like.
    var it: nftables.nl.MessageIterator = .{ .buf = wire };
    _ = try it.next(); // NFNL_MSG_BATCH_BEGIN — not an nftables object

    const table = try nftables.wire.decodeTable((try it.next()).?.payload);
    std.debug.print("table: family={s} name={s}\n", .{
        @tagName(nftables.Family.fromNfproto(table.family).?),
        table.name,
    });

    const chain = try nftables.wire.decodeChain((try it.next()).?.payload);
    std.debug.print("chain: name={s} hook={?d} policy={?d}\n", .{
        chain.name,
        chain.hooknum,
        chain.policy,
    });

    const rule = try nftables.wire.decodeRule((try it.next()).?.payload);
    var exprs = rule.exprIterator();
    var n_exprs: usize = 0;
    while (try exprs.next()) |view| {
        std.debug.print("  expr[{d}]: {s}\n", .{ n_exprs, view.name });
        n_exprs += 1;
    }
}
