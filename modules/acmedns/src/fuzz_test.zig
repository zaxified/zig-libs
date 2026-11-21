// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over the two things `acmedns` reads from the
//! other side, both generic over their source of choices (`fn(comptime S,
//! *S, gpa)`):
//!
//!   - `registration`: an acme-dns `/register` reply, a valid one with a few
//!     octets damaged and maybe cut short, through `AcmeDns.parseRegistration`;
//!   - `txt`: an authoritative server's TXT reply (two records, one carrying
//!     the value in two strings), damaged the same way, decoded by `dns` and
//!     matched by `zone.txtPresent` — the verdict the propagation check acts on;
//!   - `zone`: the zone walks (`followCname`, `findZone`, `nameservers`,
//!     `nameserverIps`) against a hostile scripted DNS server on loopback: random
//!     rules answering with CNAME loops and chains, SOA/NS/A records of the wrong
//!     owner, class or type, junk rdata and error codes.
//!
//! Driver: `ACMEDNS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const dns = @import("dns");
const publishers = @import("publishers.zig");
const zone = @import("zone.zig");
const net = std.Io.net;
const zt = @import("zone_test.zig");
const netaddr = @import("netaddr");

pub const Label = enum { json_rejected, json_parsed, txt_rejected, txt_absent, txt_found, walk_followed, walk_loop, walk_failed, zone_found, zone_missing, ns_listed, ip_listed };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const registration_json =
    \\{"username":"eabcdb41-d89f-4580-826f-3e62e9755ef2","password":"pbAXVjlIOE01xbut7YnAbkhMQIkcwoHO0ek2j4Q0",
    \\"fulldomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org","subdomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf","allowfrom":[]}
;

const value = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";

/// A reply to TXT `_acme-challenge.example.org`: question, then a TXT with an
/// unrelated value and one with `value` split into two strings (the second
/// owner name compressed), as an authoritative server sends it.
const txt_reply =
    "\x12\x34\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00" ++
    "\x0f_acme-challenge\x07example\x03org\x00\x00\x10\x00\x01" ++
    "\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x06\x05other" ++
    "\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x2d\x14" ++ value[0..20] ++ "\x17" ++ value[20..];

fn damage(comptime S: type, src: *S, out: []u8, base: []const u8) usize {
    @memcpy(out[0..base.len], base);
    var len = base.len;
    for (0..src.valueRangeAtMost(u8, 0, 4)) |_| {
        const at = src.index(len);
        out[at] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
    return len;
}

fn registrationHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [registration_json.len]u8 = undefined;
    const len = damage(S, src, &buf, registration_json);
    var parsed = publishers.AcmeDns.parseRegistration(gpa, buf[0..len]) catch {
        mark(.json_rejected);
        return;
    };
    defer parsed.deinit();
    mark(.json_parsed);
}

fn txtHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [txt_reply.len]u8 = undefined;
    const len = damage(S, src, &buf, txt_reply);
    var msg = dns.decode(gpa, buf[0..len]) catch {
        mark(.txt_rejected);
        return;
    };
    defer msg.deinit();
    if (zone.txtPresent(&msg, "_acme-challenge.example.org", value)) mark(.txt_found) else mark(.txt_absent);
}

const pool = [_][]const u8{ "_acme-challenge.a.test", "a.test", "x.dele.test", "test", "A.TEST", "loop1.test", "loop2.test", "b.a.test" };
const pool_wire = [_][]const u8{ zt.wire("_acme-challenge.a.test"), zt.wire("a.test"), zt.wire("x.dele.test"), zt.wire("test"), zt.wire("A.TEST"), zt.wire("loop1.test"), zt.wire("loop2.test"), zt.wire("b.a.test") };
const junk_rdata = [_][]const u8{ "\xff\x01", "\x3f", "\xc0\x00", "\x05ab", "", "\x00" };

fn zoneHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var rules: [6]zt.Rule = undefined;
    // One script in four holds a two-name CNAME loop, which the walk starts from.
    const looped = src.valueRangeAtMost(u8, 0, 3) == 0;
    const n = if (looped) src.valueRangeAtMost(u8, 2, 6) else src.valueRangeAtMost(u8, 1, 6);
    const qtypes = [_]u16{ zt.t_cname, zt.t_cname, zt.t_soa, zt.t_soa, zt.t_ns, zt.t_a, zt.t_aaaa };
    const rcodes = [_]u4{ 0, 0, 0, 2, 3, 5 };
    const rtypes = [_]u16{ zt.t_cname, zt.t_soa, zt.t_ns, zt.t_a, zt.t_txt };
    if (looped) {
        rules[0] = .{ .name = "loop1.test", .qtype = zt.t_cname, .rdata = comptime zt.wire("loop2.test") };
        rules[1] = .{ .name = "loop2.test", .qtype = zt.t_cname, .rdata = comptime zt.wire("loop1.test") };
    }
    for (rules[0..n], 0..) |*r, ri| {
        if (looped and ri < 2) continue;
        // Half of the scripts start with a sound zone apex, so the walks get past the first hop.
        if (ri == 0 and src.valueRangeAtMost(u8, 0, 1) == 0) {
            r.* = .{ .name = "a.test", .qtype = zt.t_soa, .rdata = zt.soa_rdata };
            continue;
        }
        const name_i = src.index(pool.len);
        const qtype = qtypes[src.index(qtypes.len)];
        const rdata: ?[]const u8 = switch (src.valueRangeAtMost(u8, 0, 4)) {
            0 => null,
            1, 2 => if (qtype == zt.t_soa) zt.soa_rdata else pool_wire[src.index(pool_wire.len)],
            3 => junk_rdata[src.index(junk_rdata.len)],
            else => if (qtype == zt.t_a) "\x7f\x00\x00\x01" else pool_wire[src.index(pool_wire.len)],
        };
        r.* = .{
            .name = pool[name_i],
            .qtype = qtype,
            .rcode = rcodes[src.index(rcodes.len)],
            .rdata = rdata,
            .class = if (src.valueRangeAtMost(u8, 0, 5) == 0) 3 else 1,
            .owner = if (src.valueRangeAtMost(u8, 0, 4) == 0) pool_wire[src.index(pool_wire.len)] else null,
            .rtype = if (src.valueRangeAtMost(u8, 0, 5) == 0) rtypes[src.index(rtypes.len)] else null,
        };
    }
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var stub = zt.Stub.bind(io, rules[0..n]) catch |err| return testkit.loopbackSkip("loopback bind failed ({t})", .{err});
    const port = stub.port();
    const th = try std.Thread.spawn(.{}, zt.Stub.run, .{&stub});
    defer {
        stub.stop.store(true, .release);
        // wake the server out of its receive so the join does not wait for its poll interval
        const any: net.IpAddress = .{ .ip4 = .loopback(0) };
        if (any.bind(io, .{ .mode = .dgram })) |wake| {
            const dest: net.IpAddress = .{ .ip4 = .loopback(port) };
            wake.send(io, &dest, "x") catch {};
            wake.close(io);
        } else |_| {}
        th.join();
        stub.sock.close(io);
    }
    var r = dns.Resolver.init(io, gpa, .{ .servers = &zt.loopback, .port = port, .timeout_ms = 300, .attempts = 1, .use_hosts = false, .use_search = false });
    defer r.deinit();

    var out: [zone.max_name_len]u8 = undefined;
    const start = if (looped) "loop1.test" else pool[src.index(pool.len)];
    if (zone.followCname(&r, start, &out)) |end| {
        if (end.len == 0 or end.len > zone.max_name_len) {
            std.debug.print("followCname {s} -> '{s}'\n", .{ start, end });
            for (rules[0..n]) |ru| std.debug.print("  rule {s} qtype {d} rcode {d} rdata {?any} class {d} owner {?any} rtype {?d}\n", .{ ru.name, ru.qtype, ru.rcode, ru.rdata, ru.class, ru.owner, ru.rtype });
            return error.TestUnexpectedResult;
        }
        mark(.walk_followed);
    } else |err| switch (err) {
        error.CnameLoop => mark(.walk_loop),
        else => mark(.walk_failed),
    }
    if (zone.findZone(&r, pool[src.index(pool.len)], &out)) |z| {
        if (z.len == 0 or z.len > zone.max_name_len) {
            std.debug.print("findZone -> '{s}'\n", .{z});
            return error.TestUnexpectedResult;
        }
        mark(.zone_found);
    } else |_| mark(.zone_missing);
    if (zone.nameservers(&r, gpa, pool[src.index(pool.len)])) |names| {
        defer zone.freeNames(gpa, names);
        mark(.ns_listed);
    } else |_| {}
    if (zone.nameserverIps(&r, gpa, pool[src.index(pool.len)])) |maybe| {
        if (maybe) |ips| gpa.free(ips);
        mark(.ip_listed);
    } else |_| {}
}

/// `testing.fuzz`'s source: every choice read by a cursor from one `slice`.
const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            u8 => self.cur.byte(),
            else => @compileError("ScriptSource.value: unsupported type"),
        };
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
};

fn fuzzScript(comptime harness: anytype) fn (void, *testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            var script: [256]u8 = undefined;
            const n = smith.slice(&script);
            var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
            return harness(ScriptSource, &src, testing.allocator);
        }
    }.f;
}

test "fuzz: parseRegistration never crashes or leaks on a damaged reply" {
    try testing.fuzz({}, fuzzScript(registrationHarness), .{});
}

test "fuzz: txtPresent never crashes on a damaged TXT reply" {
    try testing.fuzz({}, fuzzScript(txtHarness), .{});
}

test "fuzz: the zone walks never crash or leak against a hostile server" {
    try testing.fuzz({}, fuzzScript(zoneHarness), .{});
}

test "fuzz driver: ACMEDNS_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ registrationHarness, .{ .prefix = "ACMEDNS_FUZZ", .name = "acmedns-registration" } },
        .{ txtHarness, .{ .prefix = "ACMEDNS_FUZZ", .name = "acmedns-txt" } },
        .{ zoneHarness, .{ .prefix = "ACMEDNS_FUZZ", .name = "acmedns-zone" } },
    });
}

test "fuzz harness: 500 seeds (60 for the zone walks) in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        try registrationHarness(fuzz_driver.Rng, &rng, testing.allocator);
        try txtHarness(fuzz_driver.Rng, &rng, testing.allocator);
        if (seed < 60) try zoneHarness(fuzz_driver.Rng, &rng, testing.allocator);
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

test "the undamaged inputs: registration parses, the value is found" {
    var parsed = try publishers.AcmeDns.parseRegistration(testing.allocator, registration_json);
    defer parsed.deinit();
    try testing.expectEqualStrings("d420c923-bbd7-4056-ab64-c3ca54c9b3cf", parsed.value.subdomain);
    var msg = try dns.decode(testing.allocator, txt_reply);
    defer msg.deinit();
    try testing.expect(zone.txtPresent(&msg, "_acme-challenge.example.org", value));
    try testing.expect(!zone.txtPresent(&msg, "_acme-challenge.example.org", "other"[0..4]));
}
