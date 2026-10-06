// SPDX-License-Identifier: MIT

//! LIVE interop of `nftables`' JSON builder against the reference consumer of
//! that JSON, `nft -j -f -` (libnftables), and the recorder that freezes what
//! `nft` made of it into `src/testdata/nft_json.zig`, which
//! `src/json_oracle_test.zig` replays with no `nft`, no root and no netns.
//!
//! ## Why this is a PROGRAM and not a test
//!
//! Applying a ruleset needs CAP_NET_ADMIN, so the live checks in `root.zig`
//! and `consistency.zig` only run under `unshare -rn`; offline, the JSON
//! builder was pinned only by goldens written from our own reading of the
//! schema. This program takes `nft`'s word once and the module's lane
//! replays it everywhere.
//!
//! ## Usage
//!
//!     unshare -rn zig build interop-nftables                # check
//!     unshare -rn zig build interop-nftables -- --capture   # ...and rewrite the transcript
//!
//! ## What is recorded
//!
//! For each scenario in `scenarios` (the same function body as in
//! `src/json_oracle_test.zig`, which requires byte-identical JSON so the two
//! copies cannot drift apart unnoticed): the builder's JSON, the exit code of
//! `nft -j -f -` applying it on an empty ruleset, and `nft -j list ruleset`
//! afterwards -- the kernel's state as `nft` decompiles it.

const std = @import("std");
const nf = @import("nftables");

const transcript_path = "modules/nftables/src/testdata/nft_json.zig";

const Scenario = struct { name: []const u8, json: []u8 };

// ── the scenarios (keep identical to src/json_oracle_test.zig) ──────────────

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

// ── running nft ─────────────────────────────────────────────────────────────

const nft_candidates = [_][]const u8{ "/usr/sbin/nft", "/sbin/nft", "nft" };

fn nft(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8, stdin: []const u8) !struct { code: u8, stdout: []u8 } {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    var child: std.process.Child = for (nft_candidates) |a0| {
        argv.clearRetainingCapacity();
        try argv.append(gpa, a0);
        try argv.appendSlice(gpa, args);
        break std.process.spawn(io, .{ .argv = argv.items, .stdin = .pipe, .stdout = .pipe, .stderr = .inherit }) catch continue;
    } else return error.NoNft;
    var wbuf: [4096]u8 = undefined;
    var w = child.stdin.?.writer(io, &wbuf);
    try w.interface.writeAll(stdin);
    try w.interface.flush();
    child.stdin.?.close(io);
    child.stdin = null;
    var rbuf: [4096]u8 = undefined;
    var r = child.stdout.?.reader(io, &rbuf);
    const out = try r.interface.allocRemaining(gpa, .unlimited);
    const term = try child.wait(io);
    return .{ .code = switch (term) {
        .exited => |c| c,
        else => 255,
    }, .stdout = out };
}

fn zigString(gpa: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    try out.append(gpa, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(gpa, "\\\""),
        '\\' => try out.appendSlice(gpa, "\\\\"),
        '\n' => try out.appendSlice(gpa, "\\n"),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try out.append(gpa, c),
        else => try out.print(gpa, "\\x{x:0>2}", .{c}),
    };
    try out.append(gpa, '"');
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var capture = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) capture = true else {
            std.debug.print("usage: unshare -rn zig build interop-nftables [-- --capture]\n", .{});
            return 2;
        }
    }
    if (std.os.linux.geteuid() != 0) {
        std.debug.print("interop-nftables: needs euid 0 -- run it under `unshare -rn`\n", .{});
        return 2;
    }

    var list: std.ArrayList(Scenario) = .empty;
    defer {
        for (list.items) |s| gpa.free(s.json);
        list.deinit(gpa);
    }
    try scenarios(gpa, &list);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try out.appendSlice(gpa, "// SPDX-License-Identifier: MIT\n" ++
        "// Generated by `unshare -rn zig build interop-nftables -- --capture`\n" ++
        "// (modules/nftables/tools/interop.zig): this module's JSON applied by a real\n" ++
        "// `nft -j -f -`, and the ruleset `nft -j list ruleset` read back. Replayed by\n" ++
        "// src/json_oracle_test.zig. Do not edit by hand.\n\n");
    const ver = try nft(gpa, io, &.{"--version"}, "");
    defer gpa.free(ver.stdout);
    try out.appendSlice(gpa, "pub const nft_version = ");
    try zigString(gpa, &out, std.mem.trim(u8, ver.stdout, " \n"));
    try out.appendSlice(gpa, ";\n\npub const Record = struct { name: []const u8, json: []const u8, exit: u8, listing: []const u8 };\n\npub const records = [_]Record{\n");

    for (list.items) |s| {
        const fl = try nft(gpa, io, &.{ "flush", "ruleset" }, "");
        gpa.free(fl.stdout);
        if (fl.code != 0) return error.FlushFailed;
        const ap = try nft(gpa, io, &.{ "-j", "-f", "-" }, s.json);
        gpa.free(ap.stdout);
        const ls = try nft(gpa, io, &.{ "-j", "list", "ruleset" }, "");
        defer gpa.free(ls.stdout);
        std.debug.print("{s}: nft exit {d}\n", .{ s.name, ap.code });
        try out.appendSlice(gpa, "    .{ .name = ");
        try zigString(gpa, &out, s.name);
        try out.appendSlice(gpa, ", .json = ");
        try zigString(gpa, &out, s.json);
        try out.print(gpa, ", .exit = {d}, .listing = ", .{ap.code});
        try zigString(gpa, &out, std.mem.trim(u8, ls.stdout, " \n"));
        try out.appendSlice(gpa, " },\n");
    }
    try out.appendSlice(gpa, "};\n");
    if (capture) {
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = transcript_path, .data = out.items });
        std.debug.print("interop-nftables: transcript written to {s}\n", .{transcript_path});
    }
    return 0;
}
