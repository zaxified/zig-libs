// SPDX-License-Identifier: MIT

//! **External anchor for the JSON builder: what a real `nft` made of it.**
//!
//! `testdata/nft_json.zig` was taken by `tools/interop.zig` (`unshare -rn zig
//! build interop-nftables -- --capture`): each scenario below was applied with
//! `nft -j -f -` on an empty ruleset and read back with `nft -j list
//! ruleset`. Here, with no `nft` and no privileges:
//!
//! - the builder must still emit exactly the JSON `nft` was given (so the
//!   scenario code here and in the tool cannot drift apart unnoticed);
//! - `nft` must have accepted it (or refused it, where refusal is the point);
//! - every object and rule we add must come back from the kernel carrying
//!   every field we sent, with the value we sent: `nft` may add what we left
//!   to it (handles, a counter's zero counts, an element's `expires`), it may
//!   not lose or change anything. Rules compare in order per chain, and each
//!   chain must hold exactly the rules we added.
//!
//! Two renderings are normalised, both `nft` adding state: a statement we
//! send without options (`{"counter":null}`) matches any options `nft`
//! lists; an element `nft` wraps as `{"elem":{"val":X,...}}` (a set with
//! timeouts lists each element's expiry) matches our `X`.

const std = @import("std");
const testing = std.testing;
const nf = @import("root.zig");
const rec = @import("testdata/nft_json.zig");

const Scenario = struct { name: []const u8, json: []u8 };

// ── the scenarios (keep identical to tools/interop.zig) ─────────────────────

fn scenarios(gpa: std.mem.Allocator, out: *std.ArrayList(Scenario)) !void {
    {
        var rs = nf.Ruleset.init(gpa);
        defer rs.deinit();
        try rs.flushRuleset();
        try rs.addTable(.inet, "filter");
        try rs.addChain(nf.Chain.base(.inet, "filter", "input", .filter, .input, 0, .drop));
        var r1 = rs.rule(.inet, "filter", "input");
        try r1.ctState(&.{ "established", "related" }).accept().apply();
        var r2 = rs.rule(.inet, "filter", "input");
        try r2.tcpDport(nf.num(22)).accept().apply();
        var r3 = rs.rule(.inet, "filter", "input");
        try r3.l4proto("icmp").accept().apply();
        var r4 = rs.rule(.inet, "filter", "input");
        try r4.ipSaddr(nf.cidr("10.0.0.0", 8)).udpDport(nf.num(53)).counter().accept().apply();
        var r5 = rs.rule(.inet, "filter", "input");
        try r5.iifname("lo").accept().apply();
        try out.append(gpa, .{ .name = "filter", .json = try rs.toJson(gpa) });
    }
    {
        var rs = nf.Ruleset.init(gpa);
        defer rs.deinit();
        try rs.addTable(.ip, "nat");
        try rs.addChain(nf.Chain.base(.ip, "nat", "postrouting", .nat, .postrouting, 100, .accept));
        var r = rs.rule(.ip, "nat", "postrouting");
        try r.oifname("eth0").masquerade().apply();
        try out.append(gpa, .{ .name = "nat", .json = try rs.toJson(gpa) });
    }
    {
        var rs = nf.Ruleset.init(gpa);
        defer rs.deinit();
        try rs.addTable(.inet, "filter");
        try rs.addChain(nf.Chain.regular(.inet, "filter", "input"));
        try rs.addSet(.{
            .family = .inet,
            .table = "filter",
            .name = "allowed_ports",
            .elem_type = .inet_service,
            .flags = &.{.interval},
            .elem = &.{ nf.num(22), nf.num(80), nf.portRange(8000, 8100) },
        });
        var r = rs.rule(.inet, "filter", "input");
        try r.tcpDport(nf.setRef("allowed_ports")).accept().apply();
        try out.append(gpa, .{ .name = "named_set", .json = try rs.toJson(gpa) });
    }
    {
        var rs = nf.Ruleset.init(gpa);
        defer rs.deinit();
        try rs.addTable(.inet, "t");
        try rs.addChain(nf.Chain.base(.inet, "t", "input", .filter, .input, 0, .accept));
        try rs.addChain(nf.Chain.regular(.inet, "t", "helper"));
        try rs.addChain(nf.Chain.base(.inet, "t", "post", .nat, .postrouting, 100, .accept));
        try rs.addChain(nf.Chain.base(.inet, "t", "pre", .nat, .prerouting, -100, .accept));
        var a = rs.rule(.inet, "t", "input");
        try a.tcpDport(nf.num(23)).reject().apply();
        var b = rs.rule(.inet, "t", "input");
        try b.tcpDport(nf.num(24)).rejectWith(.{ .type = .tcp_reset }).apply();
        var c = rs.rule(.inet, "t", "input");
        try c.rejectWith(.{ .type = .icmpx, .expr = nf.str("admin-prohibited") }).apply();
        var d = rs.rule(.inet, "t", "input");
        try d.logWith(.{}).apply();
        var e = rs.rule(.inet, "t", "input");
        try e.logWith(.{ .prefix = "ssh: ", .level = .info }).apply();
        var f = rs.rule(.inet, "t", "input");
        try f.logWith(.{ .group = 2, .snaplen = 64, .queue_threshold = 10 }).apply();
        var g = rs.rule(.inet, "t", "input");
        try g.limit(.{ .rate = 10 }).accept().apply();
        var h = rs.rule(.inet, "t", "input");
        try h.limit(.{ .rate = 1, .per = .minute, .burst = 5, .rate_unit = .kbytes, .inv = true }).drop().apply();
        var i = rs.rule(.inet, "t", "input");
        try i.jump("helper").apply();
        var j = rs.rule(.inet, "t", "helper");
        try j.counter().ret().apply();
        var k = rs.rule(.inet, "t", "post");
        try k.snat(.{ .addr = "192.0.2.1", .family = .ip, .flags = &.{ .random, .persistent } }).apply();
        var l = rs.rule(.inet, "t", "pre");
        try l.tcpDport(nf.num(80)).dnat(.{ .addr = "10.0.0.5", .family = .ip, .port = 8080 }).apply();
        var m = rs.rule(.inet, "t", "pre");
        try m.tcpDport(nf.num(81)).push(.{ .redirect = 8081 }).apply();
        try out.append(gpa, .{ .name = "statements", .json = try rs.toJson(gpa) });
    }
    {
        var rs = nf.Ruleset.init(gpa);
        defer rs.deinit();
        try rs.addTable(.ip, "t");
        try rs.addSet(.{
            .family = .ip,
            .table = "t",
            .name = "s",
            .elem_type = .ipv4_addr,
            .flags = &.{ .interval, .timeout },
            .elem = &.{nf.cidr("10.0.0.0", 8)},
            .timeout = 600,
            .size = 1024,
            .auto_merge = true,
        });
        try rs.addChain(nf.Chain.regular(.ip, "t", "c"));
        var r = rs.rule(.ip, "t", "c");
        try r.ipDaddr(nf.setRef("s")).withComment("allow all").accept().apply();
        try out.append(gpa, .{ .name = "set_properties", .json = try rs.toJson(gpa) });
    }
    {
        var rs = nf.Ruleset.init(gpa);
        defer rs.deinit();
        try rs.create(.{ .table = .{ .family = .ip, .name = "t" } });
        try rs.addChain(nf.Chain.regular(.ip, "t", "c"));
        try rs.addSet(.{ .family = .ip, .table = "t", .name = "s", .elem_type = .ipv4_addr });
        var r = rs.rule(.ip, "t", "c");
        try r.accept().apply();
        try rs.flush(.{ .chain = nf.Chain.regular(.ip, "t", "c") });
        try rs.delete(.{ .set = .{ .family = .ip, .table = "t", .name = "s", .elem_type = .ipv4_addr } });
        try rs.delete(.{ .chain = nf.Chain.regular(.ip, "t", "c") });
        try rs.flush(.{ .table = .{ .family = .ip, .name = "t" } });
        try out.append(gpa, .{ .name = "commands", .json = try rs.toJson(gpa) });
    }
    {
        var rs = nf.Ruleset.init(gpa);
        defer rs.deinit();
        try rs.create(.{ .table = .{ .family = .ip, .name = "t" } });
        try rs.create(.{ .table = .{ .family = .ip, .name = "t" } });
        try out.append(gpa, .{ .name = "create_existing", .json = try rs.toJson(gpa) });
    }
}

// ── the comparison ──────────────────────────────────────────────────────────

fn numEql(a: std.json.Value, b: std.json.Value) ?bool {
    const x: f64 = switch (a) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => return null,
    };
    const y: f64 = switch (b) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => return null,
    };
    return x == y;
}

/// `ours` is carried by `theirs`: see the module comment.
fn carried(ours: std.json.Value, theirs: std.json.Value) bool {
    if (ours == .null) return true;
    if (theirs == .object and ours != .object) {
        if (theirs.object.get("elem")) |e| if (e == .object) if (e.object.get("val")) |v| return carried(ours, v);
    }
    if (numEql(ours, theirs)) |eq| return eq;
    return switch (ours) {
        .bool => |x| theirs == .bool and theirs.bool == x,
        .string => |x| theirs == .string and std.mem.eql(u8, x, theirs.string),
        .array => |x| blk: {
            if (theirs != .array or theirs.array.items.len != x.items.len) break :blk false;
            for (x.items, theirs.array.items) |a, b| if (!carried(a, b)) break :blk false;
            break :blk true;
        },
        .object => |x| blk: {
            if (theirs == .object) if (theirs.object.get("elem")) |e| if (x.get("elem") == null and e == .object) if (e.object.get("val")) |v| break :blk carried(ours, v);
            if (theirs != .object) break :blk false;
            var it = x.iterator();
            while (it.next()) |kv| {
                const t = theirs.object.get(kv.key_ptr.*) orelse break :blk false;
                if (!carried(kv.value_ptr.*, t)) break :blk false;
            }
            break :blk true;
        },
        else => false,
    };
}

fn str(v: std.json.Value, key: []const u8) ?[]const u8 {
    const x = v.object.get(key) orelse return null;
    return if (x == .string) x.string else null;
}

/// The listed objects of `kind` (`"table"`, `"rule"`, ...), in order.
fn listed(gpa: std.mem.Allocator, listing: std.json.Value, kind: []const u8) ![]std.json.Value {
    var out: std.ArrayList(std.json.Value) = .empty;
    for (listing.object.get("nftables").?.array.items) |item| {
        if (item.object.get(kind)) |body| try out.append(gpa, body);
    }
    return out.toOwnedSlice(gpa);
}

fn sameName(a: std.json.Value, b: std.json.Value) bool {
    for ([_][]const u8{ "family", "table", "name" }) |k| {
        const x = str(a, k);
        const y = str(b, k);
        if ((x == null) != (y == null)) return false;
        if (x != null and !std.mem.eql(u8, x.?, y.?)) return false;
    }
    return true;
}

/// Every object and rule `ours` adds is carried by the listing; each chain
/// holds exactly the rules added to it.
fn expectCarried(gpa: std.mem.Allocator, name: []const u8, ours: std.json.Value, listing: std.json.Value) !void {
    const rules = try listed(gpa, listing, "rule");
    var used: usize = 0;
    const cmds = ours.object.get("nftables").?.array.items;
    for (cmds, 0..) |cmd, ci| {
        const add = cmd.object.get("add") orelse cmd.object.get("create") orelse continue;
        var it = add.object.iterator();
        const kv = it.next().?;
        const kind = kv.key_ptr.*;
        const o = kv.value_ptr.*;
        if (std.mem.eql(u8, kind, "rule")) {
            // The next listed rule of the same table and chain.
            var nth: usize = 0;
            for (cmds[0..ci]) |c2| {
                const a2 = c2.object.get("add") orelse continue;
                const r2 = a2.object.get("rule") orelse continue;
                if (std.mem.eql(u8, str(r2, "table").?, str(o, "table").?) and std.mem.eql(u8, str(r2, "chain").?, str(o, "chain").?)) nth += 1;
            }
            var seen: usize = 0;
            const found = for (rules) |r| {
                if (!std.mem.eql(u8, str(r, "table").?, str(o, "table").?) or !std.mem.eql(u8, str(r, "chain").?, str(o, "chain").?)) continue;
                if (seen == nth) break r;
                seen += 1;
            } else null;
            if (found == null or !carried(o, found.?)) {
                std.debug.print("{s}: rule #{d} of chain {s} not carried by nft's listing\n", .{ name, nth, str(o, "chain").? });
                return error.TestUnexpectedResult;
            }
            used += 1;
        } else {
            const objs = try listed(gpa, listing, kind);
            const found = for (objs) |x| {
                if (sameName(o, x)) break x;
            } else null;
            if (found == null or !carried(o, found.?)) {
                std.debug.print("{s}: {s} {s} not carried by nft's listing\n", .{ name, kind, str(o, "name").? });
                return error.TestUnexpectedResult;
            }
        }
    }
    try testing.expectEqual(used, rules.len); // no rule we did not add
}

test "nft oracle: the JSON builder's output is what nft was given, and nft carried every field" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var list: std.ArrayList(Scenario) = .empty;
    try scenarios(arena, &list);
    try testing.expectEqual(rec.records.len, list.items.len);

    for (list.items, rec.records) |s, r| {
        try testing.expectEqualStrings(r.name, s.name);
        try testing.expectEqualStrings(r.json, s.json);
        const ours = try std.json.parseFromSliceLeaky(std.json.Value, arena, s.json, .{});
        const listing = try std.json.parseFromSliceLeaky(std.json.Value, arena, r.listing, .{});
        if (std.mem.eql(u8, s.name, "create_existing")) {
            // `create` refuses an existing object, and the batch is atomic:
            // nft exits non-zero and nothing of it is applied.
            try testing.expect(r.exit != 0);
            try testing.expectEqual(@as(usize, 0), (try listed(arena, listing, "table")).len);
            continue;
        }
        try testing.expectEqual(@as(u8, 0), r.exit);
        if (std.mem.eql(u8, s.name, "commands")) {
            // create/add, then flush chain, delete set, delete chain, flush
            // table: the table alone is left.
            const tables = try listed(arena, listing, "table");
            try testing.expectEqual(@as(usize, 1), tables.len);
            try testing.expectEqualStrings("t", str(tables[0], "name").?);
            for ([_][]const u8{ "chain", "set", "rule" }) |k| {
                try testing.expectEqual(@as(usize, 0), (try listed(arena, listing, k)).len);
            }
            continue;
        }
        try expectCarried(arena, s.name, ours, listing);
    }
}
