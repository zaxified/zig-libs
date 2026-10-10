// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for netconf (added 2026-10-10).
//!
//! `NETCONF_FUZZ=<runs>[,<first seed>]` runs the harnesses (testkit's fuzz
//! driver; `_ONLY` selects one by name, `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented there). Each is generic over its source of choices.
//! - `netconf-wire` (here): genuine `<hello>`, `<rpc-reply>` (data, ok, one or
//!   several rpc-errors) and `<notification>` documents, and their RFC 6242
//!   framing in both dialects (chunked with a drawn chunk size, delivered in
//!   random pieces), damaged (0-3 octets, truncation): undamaged they parse to
//!   what was written and the framer returns the payload exactly; damaged they
//!   never panic.
//! - `netconf-client` (`client.zig`, beside the `FakePeer`): a whole session
//!   (hello, get-config, lock refused with an rpc-error, discard-changes,
//!   close-session) whose peer-to-client byte stream is damaged / truncated /
//!   garbled / doubled at one read: the client ends each call in a typed error
//!   or a reply, and a reply it hands back is for the message-id it sent.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const capabilities = @import("capabilities.zig");
const framing = @import("framing.zig");
const reply_mod = @import("reply.zig");
pub const fuzz_driver = testkit.fuzz.driver;

/// `frame` into `buf` with 0-3 octets damaged (half within the first 48: the
/// root element, framing headers) and maybe truncated. The driver's `Rng`.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        const span = if (src.value(bool)) @min(n, 48) else n;
        buf[src.index(span)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels (see jwt's fuzz_test.zig).
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

const WireMark = Marker(enum {
    hello_ok,
    reply_ok,
    reply_data,
    reply_errors,
    notification_ok,
    damaged_accepted,
    damaged_refused,
    framed_eom,
    framed_chunked,
    framing_refused,
    classified,
});

const base_ns = capabilities.base_ns;
const error_tags = [_][]const u8{ "in-use", "invalid-value", "too-big", "missing-attribute", "lock-denied", "access-denied", "data-exists", "operation-failed", "malformed-message", "some-vendor-tag" };

const error_types = [_][]const u8{ "transport", "rpc", "protocol", "application" };

const Kind = enum { hello, reply_ok, reply_data, reply_error, notification };

pub fn fuzzWire(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const w = &aw.writer;
    var kind: Kind = .hello;
    var id_buf: [24]u8 = undefined;
    const id = std.fmt.bufPrint(&id_buf, "{d}", .{src.value(u32)}) catch unreachable;
    var raw_mode = false;
    var tmp: [3000]u8 = undefined;
    if (S == fuzz_driver.Rng) {
        kind = @enumFromInt(src.index(5));
        raw_mode = src.valueRangeAtMost(u8, 0, 9) == 0;
    } else raw_mode = true;
    var n_caps: usize = 0;
    var with_sid = false;
    switch (kind) {
        .hello => {
            const uris = [_][]const u8{
                capabilities.cap_base_1_0,
                capabilities.cap_base_1_1,
                capabilities.cap_candidate,
                capabilities.cap_validate,
                capabilities.cap_url,
                "http://example.com/vendor?module=a&revision=2026-01-01",
            };
            n_caps = 1 + src.index(uris.len);
            with_sid = src.value(bool);
            try capabilities.writeHello(w, uris[0..n_caps], if (with_sid) src.value(u32) else null);
        },
        .reply_ok => try w.print("<rpc-reply message-id=\"{s}\" xmlns=\"{s}\"><ok/></rpc-reply>", .{ id, base_ns }),
        .reply_data => try w.print("<rpc-reply message-id=\"{s}\" xmlns=\"{s}\"><data><top xmlns=\"http://example.com/c\"><a>1</a><b>&amp;</b></top></data></rpc-reply>", .{ id, base_ns }),
        .reply_error => {
            try w.print("<rpc-reply message-id=\"{s}\" xmlns=\"{s}\">", .{ id, base_ns });
            for (0..1 + src.index(3)) |_| {
                try w.print("<rpc-error><error-type>{s}</error-type><error-tag>{s}</error-tag><error-severity>{s}</error-severity><error-message xml:lang=\"en\">x</error-message><error-info><bad-element>y</bad-element></error-info></rpc-error>", .{
                    error_types[src.index(error_types.len)],
                    error_tags[src.index(error_tags.len)],
                    if (src.value(bool)) "error" else "warning",
                });
            }
            try w.writeAll("</rpc-reply>");
        },
        .notification => try w.writeAll("<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>2026-10-10T10:00:00Z</eventTime><event xmlns=\"http://example.com/e\"><severity>major</severity></event></notification>"),
    }
    const genuine = aw.written();
    var input: []const u8 = genuine;
    var changed = false;
    if (raw_mode) {
        input = tmp[0..src.slice(&tmp)];
        changed = true;
    } else if (S == fuzz_driver.Rng and src.valueRangeAtMost(u8, 0, 2) != 0) {
        const n = damage(src, &tmp, genuine);
        changed = n != genuine.len or !std.mem.eql(u8, tmp[0..n], genuine);
        input = tmp[0..n];
    }

    // Every parser, on every input.
    if (reply_mod.classify(input) != .unknown) WireMark.mark(.classified);
    var accepted = false;
    if (capabilities.parseHello(gpa, input, if (with_sid) .server else .client)) |h| {
        var hh = h;
        defer hh.deinit();
        accepted = true;
        if (!changed and kind == .hello) {
            if (hh.capabilities.list.len != n_caps) return error.CapabilityCountChanged;
            WireMark.mark(.hello_ok);
        }
    } else |_| if (!changed and kind == .hello) return error.GenuineHelloRefused;
    if (capabilities.parseHello(gpa, input, if (with_sid) .client else .server)) |h| {
        var hh = h;
        hh.deinit();
    } else |_| {}
    if (reply_mod.parseReply(gpa, input)) |r| {
        var rr = r;
        defer rr.deinit();
        accepted = true;
        if (!changed) {
            switch (kind) {
                .reply_ok, .reply_data, .reply_error => {
                    const got = rr.message_id orelse return error.MessageIdLost;
                    if (!std.mem.eql(u8, got, id)) return error.MessageIdChanged;
                    WireMark.mark(.reply_ok);
                    if (kind == .reply_data) {
                        _ = rr.expectData() catch return error.DataLost;
                        WireMark.mark(.reply_data);
                    }
                    if (kind == .reply_error) {
                        if (!rr.hasErrors()) return error.ErrorsLost;
                        WireMark.mark(.reply_errors);
                    }
                    if (kind == .reply_ok) rr.expectOk() catch return error.OkLost;
                },
                else => {},
            }
        }
        _ = rr.firstError();
    } else |_| if (!changed and (kind == .reply_ok or kind == .reply_data or kind == .reply_error)) return error.GenuineReplyRefused;
    if (reply_mod.parseNotification(gpa, input)) |n| {
        var nn = n;
        defer nn.deinit();
        accepted = true;
        if (!changed and kind == .notification) WireMark.mark(.notification_ok);
    } else |_| if (!changed and kind == .notification) return error.GenuineNotificationRefused;
    if (changed) {
        if (accepted) WireMark.mark(.damaged_accepted) else WireMark.mark(.damaged_refused);
    }

    // Framing: the genuine payload in either dialect, delivered in pieces; or damaged wire bytes.
    const dialect: framing.Dialect = if (S == fuzz_driver.Rng and src.value(bool)) .chunked else .end_of_message;
    var fw: std.Io.Writer.Allocating = .init(gpa);
    defer fw.deinit();
    if (dialect == .chunked and src.value(bool)) {
        try framing.writeChunked(&fw.writer, genuine, 1 + src.index(64));
    } else try framing.writeMessage(&fw.writer, dialect, genuine);
    const framed = fw.written();
    var wire: []const u8 = framed;
    var wire_buf: [4096]u8 = undefined;
    var wire_changed = false;
    if (S == fuzz_driver.Rng and src.valueRangeAtMost(u8, 0, 2) == 0 and framed.len <= wire_buf.len) {
        const n = damage(src, &wire_buf, framed);
        wire_changed = n != framed.len or !std.mem.eql(u8, wire_buf[0..n], framed);
        wire = wire_buf[0..n];
    }
    var fr = framing.Framer.init(gpa, dialect, .{});
    defer fr.deinit();
    var off: usize = 0;
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(gpa);
    var got_one = false;
    var failed = false;
    while (off < wire.len and !failed) {
        const take = @min(wire.len - off, 1 + src.index(97));
        fr.feed(wire[off..][0..take]) catch {
            failed = true;
            break;
        };
        off += take;
        while (fr.next() catch blk: {
            failed = true;
            break :blk null;
        }) |m| {
            // `m` is valid until the next call: keep the first by value.
            if (!got_one) {
                try first.appendSlice(gpa, m);
                got_one = true;
            }
        }
    }
    if (!wire_changed) {
        // End-of-message framing puts a newline before the delimiter
        // (`writeMessage`); the payload is what is left without it.
        const got_payload = if (dialect == .end_of_message) std.mem.trimEnd(u8, first.items, "\n") else first.items;
        const want = if (dialect == .end_of_message) std.mem.trimEnd(u8, genuine, "\n") else genuine;
        if (failed or !got_one or !std.mem.eql(u8, got_payload, want)) return error.FramerChangedThePayload;
        if (dialect == .chunked) WireMark.mark(.framed_chunked) else WireMark.mark(.framed_eom);
    } else if (failed) WireMark.mark(.framing_refused);
}

fn fuzzWireSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzWire(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: NETCONF messages and their framing, damaged, never panic" {
    try testing.fuzz({}, fuzzWireSmith, .{});
}

test "fuzz driver: NETCONF_FUZZ (wire)" {
    try fuzz_driver.run(fuzzWire, .{ .prefix = "NETCONF_FUZZ", .name = "netconf-wire" });
}

test "fuzz harness: wire, 500 seeds, reaches every outcome" {
    try WireMark.reach(fuzzWire, "netconf-wire", 500);
}
