// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over dns's wire decoder (added 2026-10-09). Two
//! harnesses, both generic over their source of choices
//! (`fn(comptime S, *S, gpa)`):
//!
//!   - `decode`: arbitrary bytes, as `testing.fuzz` always drew them. Random
//!     bytes almost never carry a header whose counts the body satisfies, so
//!     this one is the "rejected" side;
//!   - `decode-mutated`: one of the six live captures (`goldens.zig`), a few
//!     octets damaged, maybe cut short -- reaches the record parsers;
//!   - `tsig-verify` (2026-10-16): one of dnspython's TSIG-signed messages
//!     (`tsig_vectors.zig`), damaged the same way -- `tsig.verify` walks the
//!     whole message to its last record, and a server reply is hostile input;
//!   - `query-roundtrip` (2026-11-02): random `QueryOptions` (id, RD/AD/CD, DO,
//!     EDNS size or none, up to four EDNS options) and a random name;
//!     `encodeQuery` either refuses with its documented error or produces
//!     bytes that `decode` reads back to exactly those options.
//!
//!   - `rdata` (2026-11-02): arbitrary or damaged-vector rdata of TLSA / SSHFP /
//!     URI / NAPTR / SVCB / HTTPS through `rdata.parse`, under a fail-index
//!     loop over a `FailingAllocator`;
//!
//!   - `srv-order` (2026-11-02): random SRV / MX record sets through the pure
//!     ordering functions of the typed lookups (`Resolver.orderSrv`,
//!     `orderMx`): the output is a permutation of the input, priorities /
//!     preferences never decrease, nothing panics;
//!
//! Driver: `DNS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const message = @import("message.zig");
const goldens = @import("goldens.zig");
const tsig = @import("tsig.zig");
const tsig_vectors = @import("tsig_vectors.zig");
const rdata = @import("rdata.zig");
const rdata_vectors = @import("rdata_vectors.zig");
const Resolver = @import("Resolver.zig");

pub const Label = enum { rejected, decoded, with_records, tsig_rejected, tsig_verified, query_roundtrip, query_refused, rdata_tlsa_ok, rdata_tlsa_bad, rdata_sshfp_ok, rdata_sshfp_bad, rdata_uri_ok, rdata_uri_bad, rdata_naptr_ok, rdata_naptr_bad, rdata_svcb_ok, rdata_svcb_bad, srv_order, srv_order_group };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input
/// (a ranged `Smith` draw first collapses every seed to one, `check-fuzz-reach`).
const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            bool => self.cur.byte() & 1 == 1,
            u8 => self.cur.byte(),
            u16 => self.cur.word(),
            else => @compileError("ScriptSource.value: unsupported type"),
        };
    }
    pub fn bytes(self: *ScriptSource, buf: []u8) void {
        for (buf) |*b| b.* = self.cur.byte();
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
    /// What `Smith.slice` would have returned for this script: up to
    /// `buf.len` of the remaining script bytes, and their count.
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

fn walk(gpa: std.mem.Allocator, packet: []const u8) !void {
    var msg = message.decode(gpa, packet) catch {
        mark(.rejected);
        return;
    };
    defer msg.deinit();
    mark(.decoded);
    if (msg.answers.len + msg.authorities.len + msg.additionals.len != 0) mark(.with_records);
}

fn decodeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var packet: [512]u8 = undefined;
    // One `slice` draw -- never `bytes` followed by a ranged length.
    const len: usize = src.slice(&packet);
    try walk(gpa, packet[0..len]);
}

const captures = [_][]const u8{
    goldens.a_example_com,
    goldens.aaaa_example_com,
    goldens.cname_chain_wikipedia,
    goldens.mx_iana_org,
    goldens.txt_example_com,
    goldens.nxdomain_zig_libs_test,
};

fn mutatedHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var packet: [512]u8 = undefined;
    const g = captures[src.index(captures.len)];
    @memcpy(packet[0..g.len], g);
    var len: usize = g.len;
    for (0..src.valueRangeAtMost(u8, 0, 4)) |_| {
        const at = src.index(len);
        packet[at] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
    try walk(gpa, packet[0..len]);
}

fn tsigHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var packet: [512]u8 = undefined;
    const v = tsig_vectors.signed[src.index(tsig_vectors.signed.len)];
    @memcpy(packet[0..v.signed.len], v.signed);
    var len: usize = v.signed.len;
    for (0..src.valueRangeAtMost(u8, 0, 4)) |_| {
        const at = src.index(len);
        packet[at] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
    const key: tsig.Key = .{ .name = v.key_name, .algorithm = v.algorithm, .secret = v.secret };
    var mac: tsig.Mac = undefined;
    if (tsig.verify(packet[0..len], &key, .{ .now = v.time, .request_mac = v.request_mac }, &mac)) |_| {
        mark(.tsig_verified);
    } else |_| mark(.tsig_rejected);
}

fn queryHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    // A name of 1-5 labels, sometimes an over-long label or an empty one.
    var name_buf: [5 * 64 + 4]u8 = undefined; // 5 labels of up to 64 + dots
    var nlen: usize = 0;
    const labels = src.valueRangeAtMost(u8, 1, 5);
    for (0..labels) |li| {
        if (li != 0) {
            name_buf[nlen] = '.';
            nlen += 1;
        }
        const ll: usize = switch (src.valueRangeAtMost(u8, 0, 9)) {
            0 => 0, // empty label: BadName
            1 => 64, // over-long label: BadName
            else => src.valueRangeAtMost(u8, 1, 20),
        };
        for (0..ll) |_| {
            name_buf[nlen] = 'a' + src.valueRangeAtMost(u8, 0, 25);
            nlen += 1;
        }
    }
    const name = name_buf[0..nlen];

    var opt_data: [4][160]u8 = undefined;
    var opts: [4]message.EdnsOption = undefined;
    const n_opts = src.valueRangeAtMost(u8, 0, 4);
    for (0..n_opts) |i| {
        const dl: usize = if (src.valueRangeAtMost(u8, 0, 7) == 0) 140 else src.valueRangeAtMost(u8, 0, 24);
        src.bytes(opt_data[i][0..dl]);
        opts[i] = .{ .code = src.value(u16), .data = opt_data[i][0..dl] };
    }
    const options: message.QueryOptions = .{
        .id = src.value(u16),
        .recursion_desired = src.value(bool),
        .authentic_data = src.value(bool),
        .checking_disabled = src.value(bool),
        .dnssec_ok = src.value(bool),
        .edns_udp_size = if (src.valueRangeAtMost(u8, 0, 3) == 0) null else 512 + @as(u16, src.valueRangeAtMost(u8, 0, 200)) * 16,
        .edns_options = opts[0..n_opts],
    };
    var buf: [message.max_query_len]u8 = undefined;
    const q = message.encodeQuery(&buf, name, .a, options) catch |e| {
        // Only the documented refusals, each for its documented reason.
        switch (e) {
            error.BadName, error.NameTooLong => {},
            error.EdnsRequired => if (options.edns_udp_size != null or (!options.dnssec_ok and n_opts == 0)) return e,
            error.TooManyOptions => {
                var total: usize = 0;
                for (opts[0..n_opts]) |o| total += 4 + o.data.len;
                if (total <= message.max_edns_options_len) return e;
            },
            error.BufferTooSmall => return e, // max_query_len must always fit
        }
        mark(.query_refused);
        return;
    };
    errdefer std.debug.print("query-roundtrip: name \"{s}\" options {any}\n", .{ name, options });
    var m = try message.decode(gpa, q);
    defer m.deinit();
    try testing.expectEqual(options.id, m.header.id);
    try testing.expectEqual(options.recursion_desired, m.header.recursion_desired);
    try testing.expectEqual(options.authentic_data, m.header.authentic_data);
    try testing.expectEqual(options.checking_disabled, m.header.checking_disabled);
    try testing.expect(!m.header.response);
    try testing.expectEqual(@as(usize, 1), m.questions.len);
    // One trailing dot is accepted and not part of the decoded name; the root
    // ("" or ".") decodes as whatever `decode` spells the root.
    const want = if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    const got = m.questions[0].name;
    const got_n = if (got.len > 0 and got[got.len - 1] == '.') got[0 .. got.len - 1] else got;
    if (!std.ascii.eqlIgnoreCase(want, got_n)) {
        std.debug.print("query-roundtrip: decoded name \"{s}\"\n", .{m.questions[0].name});
        return error.NameMismatch;
    }
    if (options.edns_udp_size) |size| {
        try testing.expectEqual(@as(usize, 1), m.additionals.len);
        const opt = m.additionals[0].data.opt;
        try testing.expectEqual(size, opt.udp_payload_size);
        try testing.expectEqual(options.dnssec_ok, opt.dnssec_ok);
        // The raw option stream is exactly the options, in order.
        var at: usize = 0;
        for (opts[0..n_opts]) |o| {
            try testing.expectEqual(o.code, std.mem.readInt(u16, opt.options[at..][0..2], .big));
            try testing.expectEqual(o.data.len, std.mem.readInt(u16, opt.options[at + 2 ..][0..2], .big));
            try testing.expectEqualSlices(u8, o.data, opt.options[at + 4 ..][0..o.data.len]);
            at += 4 + o.data.len;
        }
        try testing.expectEqual(opt.options.len, at);
    } else try testing.expectEqual(@as(usize, 0), m.additionals.len);
    mark(.query_roundtrip);
}

/// `dns-rdata` (2026-11-02): arbitrary bytes, or a dnspython vector damaged a
/// few octets / cut short, as the rdata of each type `rdata.parse` reads.
/// The input is copied into an exact-size allocation (a read past the end is
/// then the allocator's to see), and the parse runs under its own fail-index
/// loop: every allocation in turn fails with `OutOfMemory`, nothing else may
/// leak or panic. A success also walks every accessor.
fn rdataRun(which: usize, arena: std.mem.Allocator, wire: []const u8) rdata.ParseError!void {
    const rec: message.Record = .{
        .name = "x.example",
        .ty = switch (which) {
            0 => .tlsa,
            1 => .sshfp,
            2 => .uri,
            3 => .naptr,
            4 => .svcb,
            else => .https,
        },
        .class = .in,
        .ttl = 0,
        .data = .{ .unknown = wire },
    };
    switch (which) {
        0 => _ = try rdata.parse(rdata.Tlsa, arena, rec),
        1 => _ = try rdata.parse(rdata.Sshfp, arena, rec),
        2 => _ = try rdata.parse(rdata.Uri, arena, rec),
        3 => _ = try rdata.parse(rdata.Naptr, arena, rec),
        else => {
            const s = try rdata.parse(rdata.Svcb, arena, rec);
            var prev: ?u16 = null;
            for (s.params) |p| {
                if (prev) |q| if (p.key <= q) return error.WrongType; // parser bug (keys must ascend): fails the run
                prev = p.key;
            }
            if (s.alpn()) |*it0| {
                var it = it0.*;
                while (it.next()) |id| std.mem.doNotOptimizeAway(id.len);
            }
            if (s.ipv4hint()) |*it0| {
                var it = it0.*;
                while (it.next()) |a| std.mem.doNotOptimizeAway(a);
            }
            if (s.ipv6hint()) |*it0| {
                var it = it0.*;
                while (it.next()) |a| std.mem.doNotOptimizeAway(a);
            }
            if (s.mandatory()) |*it0| {
                var it = it0.*;
                while (it.next()) |k| std.mem.doNotOptimizeAway(k);
            }
            std.mem.doNotOptimizeAway(s.port());
            std.mem.doNotOptimizeAway(s.ech());
            std.mem.doNotOptimizeAway(s.noDefaultAlpn());
        },
    }
}

fn rdataHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [320]u8 = undefined;
    const which = src.index(6);
    var len: usize = 0;
    if (src.valueRangeAtMost(u8, 0, 2) == 0) {
        len = src.slice(&buf);
    } else {
        const w: []const u8 = switch (which) {
            0 => rdata_vectors.tlsa[src.index(rdata_vectors.tlsa.len)].wire,
            1 => rdata_vectors.sshfp[src.index(rdata_vectors.sshfp.len)].wire,
            2 => rdata_vectors.uri[src.index(rdata_vectors.uri.len)].wire,
            3 => rdata_vectors.naptr[src.index(rdata_vectors.naptr.len)].wire,
            else => rdata_vectors.svcb[src.index(rdata_vectors.svcb.len)].wire,
        };
        @memcpy(buf[0..w.len], w);
        len = w.len;
        for (0..src.valueRangeAtMost(u8, 0, 3)) |_| buf[src.index(len)] = src.value(u8);
        if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len + 1);
    }
    const exact = try gpa.dupe(u8, buf[0..len]);
    defer gpa.free(exact);

    var fail: usize = 0;
    while (true) : (fail += 1) {
        if (fail > 256) return error.OomLoopRunaway;
        var fa: testing.FailingAllocator = .init(gpa, .{ .fail_index = fail });
        var arena: std.heap.ArenaAllocator = .init(fa.allocator());
        defer arena.deinit();
        if (rdataRun(which, arena.allocator(), exact)) |_| {
            switch (which) {
                0 => mark(.rdata_tlsa_ok),
                1 => mark(.rdata_sshfp_ok),
                2 => mark(.rdata_uri_ok),
                3 => mark(.rdata_naptr_ok),
                else => mark(.rdata_svcb_ok),
            }
            return;
        } else |e| switch (e) {
            error.OutOfMemory => continue,
            error.BadRecord => {
                switch (which) {
                    0 => mark(.rdata_tlsa_bad),
                    1 => mark(.rdata_sshfp_bad),
                    2 => mark(.rdata_uri_bad),
                    3 => mark(.rdata_naptr_bad),
                    else => mark(.rdata_svcb_bad),
                }
                return;
            },
            error.WrongType => return e, // `rec.ty` always matches
        }
    }
}

fn fuzzScript(comptime harness: anytype) fn (void, *testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            var script: [1024]u8 = undefined;
            const n = smith.slice(&script);
            var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
            return harness(ScriptSource, &src, testing.allocator);
        }
    }.f;
}

const decode_seeds = [_][]const u8{
    testkit.fuzz.seed(goldens.a_example_com),
    testkit.fuzz.seed(goldens.aaaa_example_com),
    testkit.fuzz.seed(goldens.cname_chain_wikipedia),
    testkit.fuzz.seed(goldens.mx_iana_org),
    testkit.fuzz.seed(goldens.txt_example_com),
    testkit.fuzz.seed(goldens.nxdomain_zig_libs_test),
    testkit.fuzz.seed("\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ "\x01a\xc0\x0c" ++ "\x00\x01\x00\x01"), // pointer cycle
    testkit.fuzz.seed("\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00" ++ "\x01a\x00\x00\x01"), // hostile ANCOUNT
    testkit.fuzz.seed("\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00" ++ "\x01a\x00" ++ "\x00\x10\x00\x01" ++ "\x00\x00\x00\x00" ++ "\x00\x03" ++ "\x09ab"), // TXT string past RDATA
};

test "fuzz: decoder never crashes or leaks on arbitrary bytes" {
    try testing.fuzz({}, fuzzScript(decodeHarness), .{ .corpus = &decode_seeds });
}

test "fuzz: decoder never crashes or leaks on damaged captures" {
    try testing.fuzz({}, fuzzScript(mutatedHarness), .{});
}

/// Seeds for `rdataHarness`: one per vector, undamaged (`which`, mode 1,
/// vector index, 0 damaged bytes, no cut).
const rdata_seeds = blk: {
    const kinds = .{ rdata_vectors.tlsa.len, rdata_vectors.sshfp.len, rdata_vectors.uri.len, rdata_vectors.naptr.len, rdata_vectors.svcb.len };
    var total = 0;
    for (kinds) |k| total += k;
    var out: [total][]const u8 = undefined;
    var n = 0;
    for (kinds, 0..) |k, which| {
        for (0..k) |i| {
            out[n] = testkit.fuzz.seed(&[_]u8{ which, 1, i, 0, 1 });
            n += 1;
        }
    }
    break :blk out;
};

/// `Resolver.orderSrv`'s `rng` over the harness's choice source.
fn SrcBelow(comptime S: type) type {
    return struct {
        src: *S,

        pub fn below(self: @This(), n: u64) u64 {
            if (n <= 1) return 0;
            return self.src.valueRangeAtMost(u32, 0, @intCast(@min(n - 1, std.math.maxInt(u32))));
        }
    };
}

const mx_hosts = [_][]const u8{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23" };

fn srvOrderHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const n = src.valueRangeAtMost(u8, 0, 24);
    // Mostly a handful of priorities (so groups form), sometimes the full range.
    const wide = src.valueRangeAtMost(u8, 0, 3) == 0;
    var orig: [24]Resolver.Srv = undefined;
    var mx: [24]Resolver.Mx = undefined;
    for (0..n) |i| {
        const priority: u16 = if (wide) src.value(u16) else src.valueRangeAtMost(u8, 0, 3);
        const weight: u16 = switch (src.valueRangeAtMost(u8, 0, 3)) {
            0 => 0,
            1 => 65535,
            else => src.valueRangeAtMost(u8, 0, 9),
        };
        orig[i] = .{ .priority = priority, .weight = weight, .port = @intCast(i), .target = "t" };
        mx[i] = .{ .preference = priority, .host = mx_hosts[i] };
    }
    var srv = orig;
    const rng = SrcBelow(S){ .src = src };
    Resolver.orderSrv(srv[0..n], rng);
    Resolver.orderMx(mx[0..n], rng);

    var seen: u32 = 0;
    var grouped = false;
    for (srv[0..n], 0..) |s, i| {
        // A permutation: each original record once, unchanged.
        const o = orig[s.port];
        try testing.expect(s.priority == o.priority and s.weight == o.weight);
        try testing.expect(seen & (@as(u32, 1) << @intCast(s.port)) == 0);
        seen |= @as(u32, 1) << @intCast(s.port);
        if (i > 0) {
            try testing.expect(srv[i - 1].priority <= s.priority);
            if (srv[i - 1].priority == s.priority) grouped = true;
        }
    }
    try testing.expectEqual(if (n == 0) @as(u32, 0) else (@as(u32, 1) << @intCast(n)) - 1, seen);

    var seen_mx: u32 = 0;
    for (mx[0..n], 0..) |m, i| {
        const id = try std.fmt.parseInt(u5, m.host, 10);
        try testing.expect(orig[id].priority == m.preference);
        try testing.expect(seen_mx & (@as(u32, 1) << id) == 0);
        seen_mx |= @as(u32, 1) << id;
        if (i > 0) try testing.expect(mx[i - 1].preference <= m.preference);
    }
    try testing.expectEqual(seen, seen_mx);
    mark(.srv_order);
    if (grouped) mark(.srv_order_group);
}

test "fuzz: SRV / MX ordering is a sorted permutation" {
    try testing.fuzz({}, fuzzScript(srvOrderHarness), .{});
}

test "fuzz: rdata.parse never crashes or leaks on arbitrary or damaged rdata" {
    try testing.fuzz({}, fuzzScript(rdataHarness), .{ .corpus = &rdata_seeds });
}

test "fuzz: tsig.verify never crashes on damaged signed messages" {
    try testing.fuzz({}, fuzzScript(tsigHarness), .{});
}

test "fuzz: encodeQuery output always decodes back to its options" {
    try testing.fuzz({}, fuzzScript(queryHarness), .{});
}

test "fuzz driver: DNS_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ decodeHarness, .{ .prefix = "DNS_FUZZ", .name = "dns-decode" } },
        .{ mutatedHarness, .{ .prefix = "DNS_FUZZ", .name = "dns-decode-mutated" } },
        .{ tsigHarness, .{ .prefix = "DNS_FUZZ", .name = "dns-tsig-verify" } },
        .{ queryHarness, .{ .prefix = "DNS_FUZZ", .name = "dns-query-roundtrip" } },
        .{ rdataHarness, .{ .prefix = "DNS_FUZZ", .name = "dns-rdata" } },
        .{ srvOrderHarness, .{ .prefix = "DNS_FUZZ", .name = "dns-srv-order" } },
    });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        decodeHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dns decode seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        mutatedHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dns mutated seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        tsigHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dns tsig seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        queryHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dns query seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        rdataHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dns rdata seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        srvOrderHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("dns srv-order seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
