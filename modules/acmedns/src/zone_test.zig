// SPDX-License-Identifier: MIT

//! The DNS walk and the propagation check against a scripted DNS server on
//! loopback: each rule answers a (name, type) with an rcode and records, so a
//! SERVFAIL or an unresolvable nameserver can be put exactly where the review
//! of 2026-10-16 found them mishandled (findings M1, M2).

const std = @import("std");
const testkit = @import("testkit");
const acme = @import("acme");
const dns = @import("dns");
const netaddr = @import("netaddr");
const root = @import("root.zig");
const zone = @import("zone.zig");
const Dns01Solver = root.Dns01Solver;

const testing = std.testing;
const net = std.Io.net;

const t_a: u16 = 1;
const t_ns: u16 = 2;
const t_cname: u16 = 5;
const t_soa: u16 = 6;
const t_txt: u16 = 16;
const t_aaaa: u16 = 28;

const servfail: u4 = 2;
const nxdomain: u4 = 3;

const Rule = struct {
    name: []const u8,
    qtype: u16,
    rcode: u4 = 0,
    /// One answer record of `qtype` with this rdata; null = none.
    rdata: ?[]const u8 = null,
};

/// `example.org` → `\x07example\x03org\x00`.
fn wire(comptime name: []const u8) []const u8 {
    comptime {
        var out: []const u8 = "";
        var it = std.mem.splitScalar(u8, name, '.');
        while (it.next()) |label| out = out ++ &[_]u8{label.len} ++ label;
        return out ++ "\x00";
    }
}

const soa_rdata = wire("ns1.a.test") ++ wire("hostmaster.a.test") ++ ("\x00\x00\x00\x01" ++ strRepeat("\x00\x00\x0e\x10", 4));

/// Answers every datagram by the first matching rules (all rules for the
/// same name and type contribute one record each), else `fallback`.
const Stub = struct {
    io: std.Io,
    sock: net.Socket,
    rules: []const Rule,
    fallback: u4 = nxdomain,
    stop: std.atomic.Value(bool) = .init(false),

    fn bind(io: std.Io, rules: []const Rule) !Stub {
        const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        return .{ .io = io, .sock = try addr.bind(io, .{ .mode = .dgram }), .rules = rules };
    }

    fn port(st: *const Stub) u16 {
        return st.sock.address.getPort();
    }

    fn run(st: *Stub) void {
        while (!st.stop.load(.acquire)) st.serveOne() catch {};
    }

    fn serveOne(st: *Stub) !void {
        var rbuf: [1500]u8 = undefined;
        const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
        const in = try st.sock.receiveTimeout(st.io, &rbuf, t.toDeadline(st.io));
        const q = in.data;
        if (q.len < 12) return;
        // The question: name labels from offset 12, then type and class.
        var name_buf: [256]u8 = undefined;
        var name_len: usize = 0;
        var at: usize = 12;
        while (at < q.len and q[at] != 0) {
            const l = q[at];
            if (at + 1 + l > q.len or name_len + l + 1 > name_buf.len) return;
            if (name_len != 0) {
                name_buf[name_len] = '.';
                name_len += 1;
            }
            @memcpy(name_buf[name_len..][0..l], q[at + 1 ..][0..l]);
            name_len += l;
            at += 1 + l;
        }
        if (at + 5 > q.len) return;
        const qtype = std.mem.readInt(u16, q[at + 1 ..][0..2], .big);
        const question = q[12 .. at + 5];
        const name = name_buf[0..name_len];

        var rcode: u4 = st.fallback;
        var answers: [8][]const u8 = undefined;
        var n: usize = 0;
        for (st.rules) |r| {
            if (r.qtype != qtype or !std.ascii.eqlIgnoreCase(r.name, name)) continue;
            rcode = r.rcode;
            if (r.rdata) |rd| if (n < answers.len) {
                answers[n] = rd;
                n += 1;
            };
        }
        var out: [1500]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try w.writeAll(q[0..2]);
        try w.writeInt(u16, 0x8180 | @as(u16, rcode), .big);
        try w.writeInt(u16, 1, .big);
        try w.writeInt(u16, @intCast(n), .big);
        try w.writeInt(u16, 0, .big);
        try w.writeInt(u16, 0, .big);
        try w.writeAll(question);
        for (answers[0..n]) |rd| {
            try w.writeAll("\xc0\x0c");
            try w.writeInt(u16, qtype, .big);
            try w.writeInt(u16, 1, .big);
            try w.writeInt(u32, 60, .big);
            try w.writeInt(u16, @intCast(rd.len), .big);
            try w.writeAll(rd);
        }
        try st.sock.send(st.io, &in.from, w.buffered());
    }
};

const loopback = [_]netaddr.Ip{.{ .v4 = .{ 127, 0, 0, 1 } }};

const Lab = struct {
    threaded: std.Io.Threaded,
    stub: Stub,
    thread: ?std.Thread = null,

    fn start(lab: *Lab, rules: []const Rule) !void {
        lab.threaded = std.Io.Threaded.init(testing.allocator, .{});
        errdefer lab.threaded.deinit();
        lab.stub = Stub.bind(lab.threaded.io(), rules) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
        lab.thread = try std.Thread.spawn(.{}, Stub.run, .{&lab.stub});
    }

    fn stop(lab: *Lab) void {
        lab.stub.stop.store(true, .release);
        if (lab.thread) |t| t.join();
        lab.stub.sock.close(lab.threaded.io());
        lab.threaded.deinit();
    }

    fn resolver(lab: *Lab) dns.Resolver {
        return dns.Resolver.init(lab.threaded.io(), testing.allocator, .{
            .servers = &loopback,
            .port = lab.stub.port(),
            .timeout_ms = 500,
            .attempts = 1,
            .use_hosts = false,
            .use_search = false,
        });
    }
};

test "followCname: a chain is followed; a SERVFAIL is an error, not \"no CNAME\" (review M2)" {
    var lab: Lab = undefined;
    try lab.start(&.{
        .{ .name = "_acme-challenge.a.test", .qtype = t_cname, .rdata = comptime wire("x.dele.test") },
        .{ .name = "x.dele.test", .qtype = t_cname }, // NOERROR, no CNAME: the end
        .{ .name = "_acme-challenge.b.test", .qtype = t_cname, .rcode = servfail },
    });
    defer lab.stop();
    var r = lab.resolver();
    defer r.deinit();
    var out: [zone.max_name_len]u8 = undefined;
    try testing.expectEqualStrings("x.dele.test", try zone.followCname(&r, "_acme-challenge.a.test", &out));
    // NXDOMAIN (the fallback) ends the walk at the name itself.
    try testing.expectEqualStrings("_acme-challenge.c.test", try zone.followCname(&r, "_acme-challenge.c.test", &out));
    try testing.expectError(error.ResolverFailed, zone.followCname(&r, "_acme-challenge.b.test", &out));
}

test "findZone: the SOA owner wins; a SERVFAIL on the way is an error, never the parent zone (review M2)" {
    var lab: Lab = undefined;
    try lab.start(&.{
        .{ .name = "a.test", .qtype = t_soa, .rdata = soa_rdata },
        .{ .name = "test", .qtype = t_soa, .rdata = soa_rdata },
        .{ .name = "b.test", .qtype = t_soa, .rcode = servfail },
    });
    defer lab.stop();
    var r = lab.resolver();
    defer r.deinit();
    var out: [zone.max_name_len]u8 = undefined;
    try testing.expectEqualStrings("a.test", try zone.findZone(&r, "_acme-challenge.x.a.test", &out));
    // Before the fix this answered "test".
    try testing.expectError(error.ResolverFailed, zone.findZone(&r, "_acme-challenge.b.test", &out));
}

const Fake = struct {
    presents: u32 = 0,
    cleanups: u32 = 0,
    fn publisher(f: *Fake) root.Publisher {
        return .{ .ctx = f, .present = present, .cleanup = cleanup };
    }
    fn present(ctx: ?*anyopaque, rec: *const root.Record) root.PublishError!void {
        _ = rec;
        const f: *Fake = @ptrCast(@alignCast(ctx.?));
        f.presents += 1;
    }
    fn cleanup(ctx: ?*anyopaque, rec: *const root.Record) void {
        _ = rec;
        const f: *Fake = @ptrCast(@alignCast(ctx.?));
        f.cleanups += 1;
    }
};

/// The zone `a.test` with NS ns1 (127.0.0.1, this stub, which has the TXT)
/// and ns2, whose address lookup answers `ns2_rcode`.
fn propagationRun(ns2_rcode: u4, require_all: bool) anyerror!void {
    const ka = "tok.thumb";
    const value = acme.jws.dns01TxtValueFromKeyAuthorization(ka);
    const txt_rdata = [_]u8{value.len} ++ value;
    const rules = [_]Rule{
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns1.a.test") },
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns2.a.test") },
        .{ .name = "ns1.a.test", .qtype = t_a, .rdata = "\x7f\x00\x00\x01" },
        .{ .name = "ns1.a.test", .qtype = t_aaaa },
        .{ .name = "ns2.a.test", .qtype = t_a, .rcode = ns2_rcode, .rdata = if (ns2_rcode == 0) "\x7f\x00\x00\x01" else null },
        .{ .name = "ns2.a.test", .qtype = t_aaaa, .rcode = ns2_rcode },
        .{ .name = "_acme-challenge.a.test", .qtype = t_txt, .rdata = &txt_rdata },
    };
    var lab: Lab = undefined;
    try lab.start(&rules);
    defer lab.stop();
    var f: Fake = .{};
    var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, .{
        .publisher = f.publisher(),
        .resolvers = &loopback,
        .port = lab.stub.port(),
        .query_timeout_ms = 300,
        .follow_cname = false,
        .zone = "a.test",
        .require_all_authoritative = require_all,
        .propagation_timeout_ms = 1200,
        .propagation_interval_ms = 100,
    });
    defer s.deinit();
    s.present("a.test", "tok", ka) catch |err| {
        // A failed wait removed what it published.
        try testing.expectEqual(f.presents, f.cleanups);
        try testing.expectEqual(@as(usize, 0), s.pendingCount());
        return err;
    };
    try testing.expectEqual(@as(usize, 1), s.pendingCount());
}

test "propagation: a nameserver whose address does not resolve holds the check (review M1)" {
    // Both nameservers resolve and answer: done.
    try propagationRun(0, true);
    // ns2's address lookup SERVFAILs: before the fix ns2 was dropped and ns1
    // alone passed the check; now it never passes.
    try testing.expectError(error.PropagationTimeout, propagationRun(servfail, true));
    // Unless one server is enough by configuration.
    try propagationRun(servfail, false);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
