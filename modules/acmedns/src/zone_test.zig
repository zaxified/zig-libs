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
    /// The record's class (1 = IN).
    class: u16 = 1,
    /// The record's owner as wire bytes; null = the question's name.
    owner: ?[]const u8 = null,
    /// The record's type; null = `qtype` (a different one is an answer of
    /// the wrong kind, as a hostile server may send).
    rtype: ?u16 = null,
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
    /// Receive and never answer: a server that is up and mute.
    silent: bool = false,
    /// The RD bit of the last query received.
    last_rd: std.atomic.Value(u8) = .init(2),
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
        if (st.silent or q.len < 12) return;
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
        st.last_rd.store(q[2] & 1, .release);

        var rcode: u4 = st.fallback;
        var answers: [8]*const Rule = undefined;
        var n: usize = 0;
        for (st.rules) |*r| {
            if (r.qtype != qtype or !std.ascii.eqlIgnoreCase(r.name, name)) continue;
            rcode = r.rcode;
            if (r.rdata != null and n < answers.len) {
                answers[n] = r;
                n += 1;
            }
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
        for (answers[0..n]) |a| {
            const rd = a.rdata.?;
            try w.writeAll(a.owner orelse "\xc0\x0c");
            try w.writeInt(u16, a.rtype orelse qtype, .big);
            try w.writeInt(u16, a.class, .big);
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
    fqdn: [256]u8 = undefined,
    fqdn_len: usize = 0,
    zone: [256]u8 = undefined,
    zone_len: usize = 0,
    /// The domains of the cleaned records, comma-separated.
    cleaned: [128]u8 = undefined,
    cleaned_len: usize = 0,
    fn publisher(f: *Fake) root.Publisher {
        return .{ .ctx = f, .present = present, .cleanup = cleanup };
    }
    fn present(ctx: ?*anyopaque, rec: *const root.Record) root.PublishError!void {
        const f: *Fake = @ptrCast(@alignCast(ctx.?));
        f.presents += 1;
        @memcpy(f.fqdn[0..rec.fqdn.len], rec.fqdn);
        f.fqdn_len = rec.fqdn.len;
        @memcpy(f.zone[0..rec.zone.len], rec.zone);
        f.zone_len = rec.zone.len;
    }
    fn cleanup(ctx: ?*anyopaque, rec: *const root.Record) void {
        const f: *Fake = @ptrCast(@alignCast(ctx.?));
        f.cleanups += 1;
        if (f.cleaned_len != 0) {
            f.cleaned[f.cleaned_len] = ',';
            f.cleaned_len += 1;
        }
        @memcpy(f.cleaned[f.cleaned_len..][0..rec.domain.len], rec.domain);
        f.cleaned_len += rec.domain.len;
    }
    fn lastFqdn(f: *const Fake) []const u8 {
        return f.fqdn[0..f.fqdn_len];
    }
    fn lastZone(f: *const Fake) []const u8 {
        return f.zone[0..f.zone_len];
    }
    fn cleanedDomains(f: *const Fake) []const u8 {
        return f.cleaned[0..f.cleaned_len];
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

fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Clock.Timestamp.now(io, .awake);
    return @intCast(@divTrunc(ts.raw.nanoseconds, std.time.ns_per_ms));
}

test "propagation: the timeout ends a pass over many mute servers, not only the pass (sweep AD-1)" {
    // Eight authoritative addresses (the list comes off the network in real
    // use: a zone's NS RRset), none answers; each query waits 300 ms. The
    // budget is 400 ms: the old code finished the whole pass (8 x 300 ms =
    // 2.4 s) before looking at the clock.
    var lab: Lab = undefined;
    try lab.start(&.{});
    defer lab.stop();
    lab.stub.silent = true;
    var f: Fake = .{};
    const auth: [8]netaddr.Ip = @splat(.{ .v4 = .{ 127, 0, 0, 1 } });
    var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, .{
        .publisher = f.publisher(),
        .port = lab.stub.port(),
        .query_timeout_ms = 300,
        .follow_cname = false,
        .zone = "a.test",
        .authoritative = &auth,
        .require_all_authoritative = false, // every server is asked in a pass
        .propagation_timeout_ms = 400,
        .propagation_interval_ms = 50,
    });
    defer s.deinit();
    const t0 = nowMs(lab.threaded.io());
    try testing.expectError(error.PropagationTimeout, s.present("a.test", "tok", "tok.thumb"));
    const took = nowMs(lab.threaded.io()) - t0;
    try testing.expect(took < 1500);
    // The mute servers were asked at all: the first query is always made.
    try testing.expectEqual(f.presents, f.cleanups);
    try testing.expectEqual(@as(usize, 0), s.pendingCount());
}

// ── mutation-run tests (2026-11-14): each pins a guard the first tests left open ──

const ka_t = "tok.thumb";

fn txtRdataOf(value: [43]u8) [44]u8 {
    var o: [44]u8 = undefined;
    o[0] = 43;
    @memcpy(o[1..], &value);
    return o;
}

const dead_ip: netaddr.Ip = .{ .v4 = .{ 127, 0, 0, 2 } }; // nothing listens there: refused at once

fn baseOpts(lab: *Lab, f: *Fake) Dns01Solver.Options {
    return .{
        .publisher = f.publisher(),
        .resolvers = &loopback,
        .port = lab.stub.port(),
        .query_timeout_ms = 300,
        .follow_cname = false,
        .zone = "a.test",
        .propagation_timeout_ms = 400,
        .propagation_interval_ms = 50,
    };
}

test "present: follow_cname walks the delegation; Options.zone beats the SOA walk" {
    var lab: Lab = undefined;
    try lab.start(&.{
        .{ .name = "_acme-challenge.a.test", .qtype = t_cname, .rdata = comptime wire("x.dele.test") },
        .{ .name = "x.dele.test", .qtype = t_cname },
        .{ .name = "dele.test", .qtype = t_soa, .rdata = soa_rdata },
    });
    defer lab.stop();
    var f: Fake = .{};
    var o = baseOpts(&lab, &f);
    o.check_propagation = false;
    o.follow_cname = true;
    o.zone = null;
    {
        var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
        defer s.deinit();
        try s.present("a.test", "tok", ka_t);
        try testing.expectEqualStrings("x.dele.test", f.lastFqdn());
        try testing.expectEqualStrings("dele.test", f.lastZone());
    }
    // A given zone is used as given, not looked up.
    o.zone = "test";
    {
        var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
        defer s.deinit();
        try s.present("a.test", "tok", ka_t);
        try testing.expectEqualStrings("test", f.lastZone());
    }
    // Without following, the name stays and no zone answers for it.
    o.follow_cname = false;
    o.zone = null;
    var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
    defer s.deinit();
    try testing.expectError(error.ZoneNotFound, s.present("a.test", "tok", ka_t));
    try testing.expectEqualStrings("no zone (SOA) found for the challenge name", s.note);
}

test "present: a zone without NS records is NoNameservers, not a timeout" {
    var lab: Lab = undefined;
    try lab.start(&.{});
    defer lab.stop();
    var f: Fake = .{};
    var o = baseOpts(&lab, &f);
    o.propagation_timeout_ms = 5000;
    var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
    defer s.deinit();
    const t0 = nowMs(lab.threaded.io());
    try testing.expectError(error.NoNameservers, s.present("a.test", "tok", ka_t));
    try testing.expect(nowMs(lab.threaded.io()) - t0 < 2000);
    try testing.expectEqualStrings("the zone has no NS records", s.note);
    try testing.expectEqual(f.presents, f.cleanups);
}

test "propagation: the sleep never runs past the timeout" {
    var lab: Lab = undefined;
    try lab.start(&.{});
    defer lab.stop();
    var f: Fake = .{};
    var o = baseOpts(&lab, &f);
    o.authoritative = &.{dead_ip};
    o.propagation_timeout_ms = 300;
    o.propagation_interval_ms = 10_000;
    var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
    defer s.deinit();
    const t0 = nowMs(lab.threaded.io());
    try testing.expectError(error.PropagationTimeout, s.present("a.test", "tok", ka_t));
    try testing.expect(nowMs(lab.threaded.io()) - t0 < 2500);
}

fn authRun(auth: []const netaddr.Ip, require_all: bool) anyerror!void {
    const value = acme.jws.dns01TxtValueFromKeyAuthorization(ka_t);
    var rd = txtRdataOf(value);
    var lab: Lab = undefined;
    try lab.start(&.{.{ .name = "_acme-challenge.a.test", .qtype = t_txt, .rdata = &rd }});
    defer lab.stop();
    var f: Fake = .{};
    var o = baseOpts(&lab, &f);
    o.authoritative = auth;
    o.require_all_authoritative = require_all;
    var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
    defer s.deinit();
    try s.present("a.test", "tok", ka_t);
    // The authoritative servers are asked with RD clear.
    try testing.expectEqual(@as(u8, 0), lab.stub.last_rd.load(.acquire));
}

test "propagation: Options.authoritative, all or any server" {
    try authRun(&loopback, true);
    try testing.expectError(error.PropagationTimeout, authRun(&.{ loopback[0], dead_ip }, true));
    try authRun(&.{ loopback[0], dead_ip }, false);
    try authRun(&.{ dead_ip, loopback[0] }, false);
    // No server has it: "one is enough" still needs one.
    try testing.expectError(error.PropagationTimeout, authRun(&.{dead_ip}, false));
}

test "propagation: a name with no address is left out; a name's second address is tried" {
    const value = acme.jws.dns01TxtValueFromKeyAuthorization(ka_t);
    var rd = txtRdataOf(value);
    const ns_nodata = [_]Rule{
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns1.a.test") },
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns2.a.test") },
        .{ .name = "ns1.a.test", .qtype = t_a, .rdata = "\x7f\x00\x00\x01" },
        .{ .name = "ns1.a.test", .qtype = t_aaaa },
        .{ .name = "ns2.a.test", .qtype = t_a },
        .{ .name = "ns2.a.test", .qtype = t_aaaa },
        .{ .name = "_acme-challenge.a.test", .qtype = t_txt, .rdata = &rd },
    };
    const two_addrs = [_]Rule{
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns1.a.test") },
        .{ .name = "ns1.a.test", .qtype = t_a, .rdata = "\x7f\x00\x00\x02" },
        .{ .name = "ns1.a.test", .qtype = t_a, .rdata = "\x7f\x00\x00\x01" },
        .{ .name = "ns1.a.test", .qtype = t_aaaa },
        .{ .name = "_acme-challenge.a.test", .qtype = t_txt, .rdata = &rd },
    };
    for ([_][]const Rule{ &ns_nodata, &two_addrs }) |rules| {
        var lab: Lab = undefined;
        try lab.start(rules);
        defer lab.stop();
        var f: Fake = .{};
        var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, baseOpts(&lab, &f));
        defer s.deinit();
        try s.present("a.test", "tok", ka_t);
    }
}

test "propagation: check_resolvers asks every recursive resolver" {
    const value = acme.jws.dns01TxtValueFromKeyAuthorization(ka_t);
    var rd = txtRdataOf(value);
    const rules = [_]Rule{
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns1.a.test") },
        .{ .name = "ns1.a.test", .qtype = t_a, .rdata = "\x7f\x00\x00\x01" },
        .{ .name = "ns1.a.test", .qtype = t_aaaa },
        .{ .name = "_acme-challenge.a.test", .qtype = t_txt, .rdata = &rd },
    };
    var lab: Lab = undefined;
    try lab.start(&rules);
    defer lab.stop();
    var f: Fake = .{};
    var o = baseOpts(&lab, &f);
    o.check_resolvers = true;
    {
        var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
        defer s.deinit();
        try s.present("a.test", "tok", ka_t);
        // The resolvers are asked last, with RD set.
        try testing.expectEqual(@as(u8, 1), lab.stub.last_rd.load(.acquire));
    }
    // A second resolver that never answers holds it, though the NS lookup
    // (which the first one serves) and the authoritative check pass.
    const two = [_]netaddr.Ip{ loopback[0], dead_ip };
    o.resolvers = &two;
    var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
    defer s.deinit();
    try testing.expectError(error.PropagationTimeout, s.present("a.test", "tok", ka_t));
    // And with the check off the same resolvers are not asked for the value.
    o.check_resolvers = false;
    var s2 = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
    defer s2.deinit();
    try s2.present("a.test", "tok", ka_t);
}

test "propagation: even a zero timeout asks once; a resolvable server that does not answer holds it" {
    const value = acme.jws.dns01TxtValueFromKeyAuthorization(ka_t);
    var rd = txtRdataOf(value);
    const rules = [_]Rule{
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns1.a.test") },
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns2.a.test") },
        .{ .name = "ns1.a.test", .qtype = t_a, .rdata = "\x7f\x00\x00\x01" },
        .{ .name = "ns1.a.test", .qtype = t_aaaa },
        .{ .name = "ns2.a.test", .qtype = t_a, .rdata = "\x7f\x00\x00\x02" },
        .{ .name = "ns2.a.test", .qtype = t_aaaa },
        .{ .name = "_acme-challenge.a.test", .qtype = t_txt, .rdata = &rd },
    };
    var lab: Lab = undefined;
    try lab.start(&rules);
    defer lab.stop();
    var f: Fake = .{};
    var o = baseOpts(&lab, &f);
    o.propagation_timeout_ms = 0;
    o.authoritative = &loopback;
    {
        var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
        defer s.deinit();
        try s.present("a.test", "tok", ka_t);
    }
    // ns2 resolves, but nothing answers there: all must, or one is enough.
    o.propagation_timeout_ms = 400;
    o.authoritative = &.{};
    {
        var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
        defer s.deinit();
        try testing.expectError(error.PropagationTimeout, s.present("a.test", "tok", ka_t));
    }
    o.require_all_authoritative = false;
    var s = Dns01Solver.init(lab.threaded.io(), testing.allocator, o);
    defer s.deinit();
    try s.present("a.test", "tok", ka_t);
}

test "present: an allocation failure during the propagation check is OutOfMemory, never a timeout (sweep AD-4)" {
    const value = acme.jws.dns01TxtValueFromKeyAuthorization(ka_t);
    var rd = txtRdataOf(value);
    const rules = [_]Rule{
        .{ .name = "a.test", .qtype = t_ns, .rdata = comptime wire("ns1.a.test") },
        .{ .name = "ns1.a.test", .qtype = t_a, .rdata = "\x7f\x00\x00\x01" },
        .{ .name = "ns1.a.test", .qtype = t_aaaa },
        .{ .name = "_acme-challenge.a.test", .qtype = t_txt, .rdata = &rd },
    };
    var lab: Lab = undefined;
    try lab.start(&rules);
    defer lab.stop();
    var saw_oom = false;
    for (0..240) |k| {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = k % 120 });
        var f: Fake = .{};
        var o = baseOpts(&lab, &f);
        o.propagation_timeout_ms = 300;
        // Second half: the authoritative list is given, not looked up.
        if (k >= 120) o.authoritative = &loopback;
        var s = Dns01Solver.init(lab.threaded.io(), failing.allocator(), o);
        defer s.deinit();
        s.present("a.test", "tok", ka_t) catch |err| {
            if (failing.has_induced_failure) {
                try testing.expectEqual(error.OutOfMemory, err);
                saw_oom = true;
            }
            try testing.expectEqual(f.presents, f.cleanups);
            try testing.expectEqual(@as(usize, 0), s.pendingCount());
        };
    }
    try testing.expect(saw_oom);
}

fn chainRules(comptime prefix: []const u8, comptime n: usize) [n]Rule {
    comptime {
        var out: [n]Rule = undefined;
        for (0..n) |i| out[i] = .{
            .name = prefix ++ &[_]u8{@as(u8, '0') + i} ++ ".t",
            .qtype = t_cname,
            .rdata = wire(prefix ++ &[_]u8{@as(u8, '0') + i + 1} ++ ".t"),
        };
        return out;
    }
}

test "followCname: eight hops are followed, nine are a loop; a cycle is a loop" {
    const rules = comptime chainRules("c", 8) ++ chainRules("d", 9) ++ [_]Rule{
        .{ .name = "la.t", .qtype = t_cname, .rdata = wire("lb.t") },
        .{ .name = "lb.t", .qtype = t_cname, .rdata = wire("la.t") },
    };
    var lab: Lab = undefined;
    try lab.start(&rules);
    defer lab.stop();
    var r = lab.resolver();
    defer r.deinit();
    var out: [zone.max_name_len]u8 = undefined;
    try testing.expectEqualStrings("c8.t", try zone.followCname(&r, "c0.t", &out));
    try testing.expectError(error.CnameLoop, zone.followCname(&r, "d0.t", &out));
    try testing.expectError(error.CnameLoop, zone.followCname(&r, "la.t", &out));
}

test "followCname / findZone / nameservers: answers of the wrong class, owner, type or rcode do not count" {
    const rules = [_]Rule{
        // followCname
        .{ .name = "fa.t", .qtype = t_cname, .rdata = comptime wire("x.t"), .class = 3 },
        .{ .name = "fb.t", .qtype = t_cname, .rdata = "\x01\x02\x03\x04", .rtype = t_a },
        .{ .name = "fc.t", .qtype = t_cname, .rdata = comptime wire("x.t"), .owner = comptime wire("other.t") },
        .{ .name = "fd.t", .qtype = t_cname, .rdata = comptime wire("first.t") },
        .{ .name = "fd.t", .qtype = t_cname, .rdata = comptime wire("second.t") },
        .{ .name = "first.t", .qtype = t_cname },
        // findZone
        .{ .name = "g.a.test", .qtype = t_soa, .rdata = soa_rdata, .class = 3 },
        .{ .name = "a.test", .qtype = t_soa, .rdata = soa_rdata },
        .{ .name = "h.b.test", .qtype = t_soa, .rdata = "\x01\x02\x03\x04", .rtype = t_a },
        .{ .name = "b.test", .qtype = t_soa, .rdata = soa_rdata },
        .{ .name = "i.c.test", .qtype = t_soa, .rdata = soa_rdata, .owner = comptime wire("z.test") },
        .{ .name = "c.test", .qtype = t_soa, .rdata = soa_rdata },
        .{ .name = "j.d.test", .qtype = t_soa, .rdata = soa_rdata, .rcode = nxdomain },
        .{ .name = "d.test", .qtype = t_soa, .rdata = soa_rdata },
        // nameservers
        .{ .name = "n.test", .qtype = t_ns, .rdata = comptime wire("ch.t"), .class = 3 },
        .{ .name = "n.test", .qtype = t_ns, .rdata = comptime wire("own.t"), .owner = comptime wire("other.t") },
        .{ .name = "n.test", .qtype = t_ns, .rdata = "\x01\x02\x03\x04", .rtype = t_a },
        .{ .name = "n.test", .qtype = t_ns, .rdata = comptime wire("real.t") },
    };
    var lab: Lab = undefined;
    try lab.start(&rules);
    defer lab.stop();
    var r = lab.resolver();
    defer r.deinit();
    var out: [zone.max_name_len]u8 = undefined;
    for ([_][]const u8{ "fa.t", "fb.t", "fc.t" }) |n| try testing.expectEqualStrings(n, try zone.followCname(&r, n, &out));
    try testing.expectEqualStrings("first.t", try zone.followCname(&r, "fd.t", &out));
    try testing.expectEqualStrings("a.test", try zone.findZone(&r, "g.a.test", &out));
    try testing.expectEqualStrings("b.test", try zone.findZone(&r, "h.b.test", &out));
    try testing.expectEqualStrings("c.test", try zone.findZone(&r, "i.c.test", &out));
    try testing.expectEqualStrings("d.test", try zone.findZone(&r, "j.d.test", &out));
    try testing.expectEqualStrings("a.test", try zone.findZone(&r, "g.a.test.", &out));
    try testing.expectError(error.ZoneNotFound, zone.findZone(&r, "nothing.zz", &out));
    try testing.expectError(error.ZoneNotFound, zone.findZone(&r, "", &out));
    const names = try zone.nameservers(&r, testing.allocator, "n.test");
    defer zone.freeNames(testing.allocator, names);
    try testing.expectEqual(@as(usize, 1), names.len);
    try testing.expectEqualStrings("real.t", names[0]);
}

test "nameserverIps: one family failing is not 'unknown'; both failing is; filters" {
    const rules = [_]Rule{
        .{ .name = "p.test", .qtype = t_a, .rdata = "\x01\x02\x03\x04" },
        .{ .name = "p.test", .qtype = t_aaaa, .rcode = servfail },
        .{ .name = "v.test", .qtype = t_a },
        .{ .name = "v.test", .qtype = t_aaaa, .rcode = servfail },
        .{ .name = "q.test", .qtype = t_a, .rcode = servfail },
        .{ .name = "q.test", .qtype = t_aaaa, .rcode = servfail },
        .{ .name = "r.test", .qtype = t_a },
        .{ .name = "r.test", .qtype = t_aaaa },
        .{ .name = "s1.test", .qtype = t_a, .rdata = "\x01\x02\x03\x04", .class = 3 },
        .{ .name = "s1.test", .qtype = t_aaaa },
        .{ .name = "s2.test", .qtype = t_a },
        .{ .name = "s2.test", .qtype = t_aaaa, .rdata = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", .owner = comptime wire("o.test") },
        .{ .name = "u.test", .qtype = t_a, .rdata = "\x01\x02\x03\x04" },
        .{ .name = "u.test", .qtype = t_aaaa, .rdata = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" },
    };
    var lab: Lab = undefined;
    try lab.start(&rules);
    defer lab.stop();
    var r = lab.resolver();
    defer r.deinit();
    const gpa = testing.allocator;
    const p = (try zone.nameserverIps(&r, gpa, "p.test")).?;
    defer gpa.free(p);
    try testing.expectEqual(@as(usize, 1), p.len);
    try testing.expect(p[0] == .v4);
    try testing.expectEqual(@as(?[]netaddr.Ip, null), try zone.nameserverIps(&r, gpa, "q.test"));
    try testing.expectEqual(@as(?[]netaddr.Ip, null), try zone.nameserverIps(&r, gpa, "v.test"));
    const e = (try zone.nameserverIps(&r, gpa, "r.test")).?;
    defer gpa.free(e);
    try testing.expectEqual(@as(usize, 0), e.len);
    const s1 = (try zone.nameserverIps(&r, gpa, "s1.test")).?;
    defer gpa.free(s1);
    try testing.expectEqual(@as(usize, 0), s1.len);
    const s2 = (try zone.nameserverIps(&r, gpa, "s2.test")).?;
    defer gpa.free(s2);
    try testing.expectEqual(@as(usize, 0), s2.len);
    const both = (try zone.nameserverIps(&r, gpa, "u.test")).?;
    defer gpa.free(both);
    try testing.expectEqual(@as(usize, 2), both.len);
}

test "nameserverIps: a server that never answers is 'unknown'; an allocation failure is an error, not 'unknown'" {
    var lab: Lab = undefined;
    try lab.start(&.{});
    defer lab.stop();
    lab.stub.silent = true;
    var r = lab.resolver();
    defer r.deinit();
    r.options.timeout_ms = 100;
    try testing.expectEqual(@as(?[]netaddr.Ip, null), try zone.nameserverIps(&r, testing.allocator, "silent.test"));
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var r2 = dns.Resolver.init(lab.threaded.io(), failing.allocator(), .{
        .servers = &loopback,
        .port = lab.stub.port(),
        .timeout_ms = 100,
        .attempts = 1,
        .use_hosts = false,
        .use_search = false,
    });
    defer r2.deinit();
    try testing.expectError(error.OutOfMemory, zone.nameserverIps(&r2, testing.allocator, "silent.test"));
}

test "serverHasTxtRd / serverHasTxtAny: the RD bit, the value, wrong-kind answers" {
    const value = acme.jws.dns01TxtValueFromKeyAuthorization(ka_t);
    var rd = txtRdataOf(value);
    const rules = [_]Rule{
        .{ .name = "t.test", .qtype = t_txt, .rdata = &rd },
        .{ .name = "u.test", .qtype = t_txt, .rdata = &rd, .class = 3 },
        .{ .name = "v.test", .qtype = t_txt, .rdata = &rd, .owner = comptime wire("o.test") },
        .{ .name = "w.test", .qtype = t_txt, .rdata = "\x01\x02\x03\x04", .rtype = t_a },
    };
    var lab: Lab = undefined;
    try lab.start(&rules);
    defer lab.stop();
    const io = lab.threaded.io();
    const port = lab.stub.port();
    const gpa = testing.allocator;
    try testing.expect(try zone.serverHasTxt(io, gpa, loopback[0], port, 500, "t.test", &value));
    try testing.expectEqual(@as(u8, 0), lab.stub.last_rd.load(.acquire));
    try testing.expect(try zone.serverHasTxtRd(io, gpa, loopback[0], port, 500, "t.test", &value, true));
    try testing.expectEqual(@as(u8, 1), lab.stub.last_rd.load(.acquire));
    try testing.expect(!try zone.serverHasTxt(io, gpa, loopback[0], port, 500, "t.test", "other"));
    try testing.expect(!try zone.serverHasTxt(io, gpa, loopback[0], port, 500, "w.test", &value));
    try testing.expect(try zone.serverHasTxtAny(io, gpa, loopback[0], port, 500, "t.test"));
    for ([_][]const u8{ "u.test", "v.test", "w.test", "none.test" }) |n| {
        try testing.expect(!try zone.serverHasTxtAny(io, gpa, loopback[0], port, 500, n));
    }
    try testing.expectEqual(@as(u8, 0), lab.stub.last_rd.load(.acquire));
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
