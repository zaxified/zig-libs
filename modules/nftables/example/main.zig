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

    const table_payload = (try it.next()).?.payload;
    const table = try nftables.wire.decodeTable(table_payload);
    std.debug.print("table: family={s} name={s}\n", .{
        @tagName(nftables.Family.fromNfproto(table.family).?),
        table.name,
    });
    // Round-trip: what came back must be what addTable() above was given.
    if (nftables.Family.fromNfproto(table.family).? != .inet) return error.TableFamilyMismatch;
    if (!std.mem.eql(u8, table.name, "filter")) return error.TableNameMismatch;

    const chain = try nftables.wire.decodeChain((try it.next()).?.payload);
    std.debug.print("chain: name={s} hook={?d} policy={?d}\n", .{
        chain.name,
        chain.hooknum,
        chain.policy,
    });
    // Round-trip against addChain() above: name verbatim, hook/policy against
    // the module's own enum->wire-value mapping (Hook.num/Policy.verdict),
    // not against numbers copied from a debug run.
    if (!std.mem.eql(u8, chain.name, "input")) return error.ChainNameMismatch;
    if (chain.hooknum != try nftables.Hook.input.num(.inet)) return error.ChainHookMismatch;
    if (chain.policy != nftables.Policy.drop.verdict()) return error.ChainPolicyMismatch;

    const rule = try nftables.wire.decodeRule((try it.next()).?.payload);
    var exprs = rule.exprIterator();
    var n_exprs: usize = 0;
    // `tcpDport(22).accept()` above chains l4proto() [meta+cmp] then
    // payloadCmp() [payload+cmp] then verdict() [immediate] — this exact
    // 5-expression shape, in this order, is what those calls are documented
    // to build.
    const expected_expr_names = [_][]const u8{ "meta", "cmp", "payload", "cmp", "immediate" };
    while (try exprs.next()) |view| {
        std.debug.print("  expr[{d}]: {s}\n", .{ n_exprs, view.name });
        if (n_exprs >= expected_expr_names.len or !std.mem.eql(u8, view.name, expected_expr_names[n_exprs])) {
            return error.RuleExprShapeMismatch;
        }
        n_exprs += 1;
    }
    if (n_exprs != expected_expr_names.len) return error.RuleExprCountMismatch;

    // A named-error path: a message payload truncated mid-attribute must be
    // rejected by name, not silently parsed into a garbage TableInfo.
    if (nftables.wire.decodeTable(table_payload[0 .. table_payload.len - 1])) |_| {
        return error.TruncatedTablePayloadUnexpectedlyAccepted;
    } else |err| switch (err) {
        error.Truncated => std.debug.print("truncated table payload correctly rejected (Truncated)\n", .{}),
        error.BadLength => std.debug.print("truncated table payload correctly rejected (BadLength)\n", .{}),
    }
}
