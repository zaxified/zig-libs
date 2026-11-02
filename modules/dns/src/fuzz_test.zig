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

pub const Label = enum { rejected, decoded, with_records, tsig_rejected, tsig_verified, query_roundtrip, query_refused };
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
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
