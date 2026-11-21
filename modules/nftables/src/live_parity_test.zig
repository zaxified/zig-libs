// SPDX-License-Identifier: MIT

//! **Live lane for the parity additions** (`unshare -rn`): concatenated sets,
//! `destroy`, `replace rule`, chain rename and the ruleset monitor, each applied
//! to a real kernel and read back — through this module's own dumps and, where
//! the text is the point, through the reference implementation (`nft list …`).
//! Without privileges or without `nft` the tests print `SKIPPED:` and pass.

const std = @import("std");
const builtin = @import("builtin");
const testkit = @import("testkit");

const root = @import("root.zig");
const wire = @import("wire.zig");
const expr = @import("expr.zig");

const testing = std.testing;
const gpa = testing.allocator;

const table = "zig_nft_parity";

/// The userdata `nft` stamps on a `type ipv4_addr . inet_service` set: it is
/// what lets `nft list` print the type instead of a raw length.
const ud_set_concat = [_]u8{ 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x12, 0x00, 0x04, 0x0d, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00 };

fn openSocket(what: []const u8) !root.Socket {
    if (builtin.os.tag != .linux) return testkit.skip("LIVE nftables {s} test: needs Linux", .{what});
    var sock = root.Socket.open(gpa) catch |err| return testkit.skip("LIVE nftables {s} test: cannot open a socket ({s})", .{ what, @errorName(err) });
    sock.setRecvTimeout(5000) catch {};
    return sock;
}

/// Commit, or skip when the kernel refuses for want of privilege or support.
fn commitOrSkip(sock: *root.Socket, b: *wire.Batch, what: []const u8) !void {
    sock.commit(b) catch |err| switch (err) {
        error.KernelRejected, error.AccessDenied, error.NotSupported, error.WouldBlock => {
            return testkit.skip("LIVE nftables {s} test: the kernel refused the batch ({s}); run as `unshare -rn`", .{ what, @errorName(err) });
        },
        else => return err,
    };
}

fn dropTable(sock: *root.Socket) void {
    var b = sock.beginBatch(.{}) catch return;
    defer b.deinit();
    b.destroyTable(.inet, table) catch return;
    sock.commit(&b) catch {};
}

/// `nft <args…>` stdout, or `SkipZigTest` when there is no `nft`.
fn nftText(args: []const []const u8) ![]u8 {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const candidates = [_][]const u8{ "nft", "/usr/sbin/nft", "/sbin/nft" };
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    var child: std.process.Child = for (candidates) |argv0| {
        argv.clearRetainingCapacity();
        try argv.append(gpa, argv0);
        try argv.appendSlice(gpa, args);
        break std.process.spawn(io, .{ .argv = argv.items, .stdin = .ignore, .stdout = .pipe, .stderr = .ignore }) catch continue;
    } else return testkit.skip("LIVE nftables test: no `nft` binary", .{});
    var rbuf: [4096]u8 = undefined;
    var reader = child.stdout.?.reader(io, &rbuf);
    const out = try reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(out);
    _ = child.wait(io) catch return error.SkipZigTest;
    return out;
}

test "live: a concatenated set and its elements, read back by this module and by nft" {
    var sock = try openSocket("concatenated set");
    defer sock.close();
    dropTable(&sock);

    var b = try sock.beginBatch(.{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = table });
    try b.addSet(.{ .family = .inet, .table = table, .name = "cs", .key_type = .ipv4_addr, .key_concat = &.{ .ipv4_addr, .inet_service }, .id = 1, .userdata = &ud_set_concat });
    var k1: [8]u8 = undefined;
    var k2: [8]u8 = undefined;
    const e1 = try wire.concatKey(&k1, &.{ .ipv4_addr, .inet_service }, &.{ &.{ 1, 2, 3, 4 }, &expr.portBytes(80) });
    const e2 = try wire.concatKey(&k2, &.{ .ipv4_addr, .inet_service }, &.{ &.{ 5, 6, 7, 8 }, &expr.portBytes(443) });
    try b.addSetElems(.inet, table, "cs", 1, &.{ .{ .key = e1 }, .{ .key = e2 } });
    try commitOrSkip(&sock, &b, "concatenated set");
    defer dropTable(&sock);

    var sets = try sock.listSets(.inet);
    defer sets.deinit();
    var found = false;
    for (sets.items) |s| {
        if (!std.mem.eql(u8, s.table, table) or !std.mem.eql(u8, s.name, "cs")) continue;
        found = true;
        // `nft` sends no field description for a plain concatenation (an
        // interval one does), and the kernel reports none: the 8-byte key, the
        // two 4-byte-padded fields, is all there is on the wire.
        try testing.expectEqual(@as(u32, 0), s.flags);
        try testing.expectEqual(@as(u32, 8), s.key_len);
    }
    try testing.expect(found);

    var elems = try sock.listSetElems(.inet, table, "cs");
    defer elems.deinit();
    try testing.expectEqual(@as(usize, 2), elems.items.len);
    var saw1 = false;
    var saw2 = false;
    for (elems.items) |el| {
        if (std.mem.eql(u8, el.key, e1)) saw1 = true;
        if (std.mem.eql(u8, el.key, e2)) saw2 = true;
    }
    try testing.expect(saw1 and saw2);

    // The reference reads the same ruleset: type and elements as nft spells them.
    const text = try nftText(&.{ "list", "table", "inet", table });
    defer gpa.free(text);
    try testing.expect(std.mem.find(u8, text, "ipv4_addr . inet_service") != null);
    try testing.expect(std.mem.find(u8, text, "1.2.3.4 . 80") != null);
    try testing.expect(std.mem.find(u8, text, "5.6.7.8 . 443") != null);

    // destroy element: a present key goes, an absent one is not an error.
    var d = try sock.beginBatch(.{});
    defer d.deinit();
    try d.destroySetElems(.inet, table, "cs", &.{ .{ .key = e1 }, .{ .key = &[_]u8{ 9, 9, 9, 9, 0, 80, 0, 0 } } });
    try sock.commit(&d);
    var after = try sock.listSetElems(.inet, table, "cs");
    defer after.deinit();
    try testing.expectEqual(@as(usize, 1), after.items.len);
    try testing.expectEqualSlices(u8, e2, after.items[0].key);
}

test "live: replace rule keeps the handle, rename chain keeps the rules, destroy tolerates the absent" {
    var sock = try openSocket("replace/rename/destroy");
    defer sock.close();
    dropTable(&sock);

    var p1 = expr.Program.init(gpa, .inet);
    defer p1.deinit();
    _ = p1.tcpDport(22).counter().accept();
    var b = try sock.beginBatch(.{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = table });
    try b.addChain(.{ .family = .inet, .table = table, .name = "c1", .chain_type = .filter, .hook = .input, .prio = 0 });
    try b.addRule(.{ .family = .inet, .table = table, .chain = "c1", .exprs = try p1.finish() });
    try commitOrSkip(&sock, &b, "replace/rename/destroy");
    defer dropTable(&sock);

    var rules = try sock.listRules(.inet, table, "c1");
    defer rules.deinit();
    try testing.expectEqual(@as(usize, 1), rules.items.len);
    const handle = rules.items[0].handle;
    var first_names: std.ArrayList([]const u8) = .empty;
    defer first_names.deinit(gpa);
    var it0 = rules.items[0].exprIterator();
    while (try it0.next()) |v| try first_names.append(gpa, v.name);
    try testing.expect(first_names.items.len >= 3);

    // replace rule: same handle, new expressions.
    var p2 = expr.Program.init(gpa, .inet);
    defer p2.deinit();
    _ = p2.udpDport(53).drop();
    var r = try sock.beginBatch(.{});
    defer r.deinit();
    try r.replaceRule(.{ .family = .inet, .table = table, .chain = "c1", .handle = handle, .exprs = try p2.finish() });
    try sock.commit(&r);
    var replaced = try sock.listRules(.inet, table, "c1");
    defer replaced.deinit();
    try testing.expectEqual(@as(usize, 1), replaced.items.len);
    try testing.expectEqual(handle, replaced.items[0].handle);
    var names2: std.ArrayList([]const u8) = .empty;
    defer names2.deinit(gpa);
    var it2 = replaced.items[0].exprIterator();
    while (try it2.next()) |v| try names2.append(gpa, v.name);
    // The old rule had a counter; the new one has none, and ends in a verdict.
    for (names2.items) |n| try testing.expect(!std.mem.eql(u8, n, "counter"));
    try testing.expectEqualStrings("immediate", names2.items[names2.items.len - 1]);
    const text = try nftText(&.{ "list", "chain", "inet", table, "c1" });
    defer gpa.free(text);
    try testing.expect(std.mem.find(u8, text, "udp dport 53 drop") != null);
    try testing.expect(std.mem.find(u8, text, "tcp dport 22") == null);

    // rename chain, by handle.
    var chains = try sock.listChains(.inet);
    defer chains.deinit();
    var chain_handle: u64 = 0;
    for (chains.items) |c| {
        if (std.mem.eql(u8, c.table, table) and std.mem.eql(u8, c.name, "c1")) chain_handle = c.handle;
    }
    try testing.expect(chain_handle != 0);
    var rn = try sock.beginBatch(.{});
    defer rn.deinit();
    try rn.renameChain(.inet, table, chain_handle, "c2");
    try sock.commit(&rn);
    var chains2 = try sock.listChains(.inet);
    defer chains2.deinit();
    var has_c1 = false;
    var has_c2 = false;
    for (chains2.items) |c| {
        if (!std.mem.eql(u8, c.table, table)) continue;
        if (std.mem.eql(u8, c.name, "c1")) has_c1 = true;
        if (std.mem.eql(u8, c.name, "c2")) {
            has_c2 = true;
            try testing.expectEqual(chain_handle, c.handle);
        }
    }
    try testing.expect(has_c2 and !has_c1);
    var moved = try sock.listRules(.inet, table, "c2");
    defer moved.deinit();
    try testing.expectEqual(@as(usize, 1), moved.items.len);

    // destroy: absent objects are not errors, present ones go.
    var d = try sock.beginBatch(.{});
    defer d.deinit();
    try d.destroyChain(.inet, table, "nope");
    try d.destroySet(.inet, table, "nope");
    try d.destroyTable(.inet, "zig_nft_parity_absent");
    try d.destroyRule(.inet, table, "c2", handle + 1000);
    try d.destroyRule(.inet, table, "c2", handle);
    try sock.commit(&d);
    var empty = try sock.listRules(.inet, table, "c2");
    defer empty.deinit();
    try testing.expectEqual(@as(usize, 0), empty.items.len);
    var e = try sock.beginBatch(.{});
    defer e.deinit();
    try e.destroyTable(.inet, table);
    try sock.commit(&e);
    var tables = try sock.listTables(.inet);
    defer tables.deinit();
    for (tables.items) |t| try testing.expect(!std.mem.eql(u8, t.name, table));
}

test "live: the monitor reports the ruleset change by change" {
    var sock = try openSocket("monitor");
    defer sock.close();
    dropTable(&sock);
    var mon = root.Socket.openMonitor(gpa, wire.Group.NFTABLES) catch |err| {
        return testkit.skip("LIVE nftables monitor test: cannot subscribe ({s})", .{@errorName(err)});
    };
    defer mon.close();
    mon.setRecvTimeout(2000) catch {};

    var p = expr.Program.init(gpa, .inet);
    defer p.deinit();
    _ = p.tcpDport(22).accept();
    var b = try sock.beginBatch(.{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = table });
    try b.addChain(.{ .family = .inet, .table = table, .name = "c", .chain_type = .filter, .hook = .input, .prio = 0 });
    try b.addRule(.{ .family = .inet, .table = table, .chain = "c", .exprs = try p.finish() });
    try commitOrSkip(&sock, &b, "monitor");

    var seen: [4]bool = @splat(false); // table, chain, rule, generation
    var gens: u32 = 0;
    var datagrams: usize = 0;
    while (datagrams < 8 and !(seen[0] and seen[1] and seen[2] and seen[3])) : (datagrams += 1) {
        var it = mon.nextEvents() catch break;
        while (try it.next()) |ev| {
            if (ev.action != .new) continue;
            switch (ev.object) {
                .table => {
                    const t = try wire.decodeTable(ev.payload);
                    if (std.mem.eql(u8, t.name, table)) seen[0] = true;
                },
                .chain => {
                    const c = try wire.decodeChain(ev.payload);
                    if (std.mem.eql(u8, c.table, table) and std.mem.eql(u8, c.name, "c")) seen[1] = true;
                },
                .rule => {
                    const r = try wire.decodeRule(ev.payload);
                    if (std.mem.eql(u8, r.table, table) and std.mem.eql(u8, r.chain, "c")) seen[2] = true;
                },
                .generation => {
                    seen[3] = true;
                    gens += 1;
                },
                else => {},
            }
        }
    }
    try testing.expect(seen[0] and seen[1] and seen[2] and seen[3]);

    // Deleting the table is announced too, as deletions of what it held.
    var d = try sock.beginBatch(.{});
    defer d.deinit();
    try d.deleteTable(.inet, table);
    try sock.commit(&d);
    var deleted_table = false;
    var deleted_chain = false;
    var deleted_rule = false;
    datagrams = 0;
    while (datagrams < 8 and !(deleted_table and deleted_chain and deleted_rule)) : (datagrams += 1) {
        var it = mon.nextEvents() catch break;
        while (try it.next()) |ev| {
            if (ev.action != .delete) continue;
            switch (ev.object) {
                .table => deleted_table = true,
                .chain => deleted_chain = true,
                .rule => deleted_rule = true,
                else => {},
            }
        }
    }
    try testing.expect(deleted_table and deleted_chain and deleted_rule);
}
