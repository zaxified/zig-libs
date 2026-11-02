// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over the receiving side (`parse.zig`), each harness
//! generic over its source of choices (`fn(comptime S, *S, gpa)`):
//!
//!   - `syslog-5424`: a well-formed line, damaged a little or not at all,
//!     through `parse`. No panic; a line it accepts has walkable SD, values that
//!     unescape, and re-encodes to something `parse` reads to the same fields.
//!   - `syslog-roundtrip`: a random `Message` through OUR encoder must always
//!     parse, field for field, after the encoder's documented sanitizing.
//!   - `syslog-3164`: lines of RFC 3164's shapes, damaged, through `parseBsd`
//!     (and `parseAny`); a random `bsd.Message` through the encoder comes back.
//!   - `syslog-frames`: frames of every framing cut into random pieces go through
//!     `nextFrame` whole; damaged streams end in an error or a wait, never more
//!     consumed than was there.
//!
//! Driver: `SYSLOG_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const message = @import("message.zig");
const bsd = @import("bsd.zig");
const parser = @import("parse.zig");
const transport = @import("transport.zig");

pub const Label = enum {
    l5424_ok,
    l5424_bad_pri,
    l5424_bad_version,
    l5424_bad_time,
    l5424_bad_header,
    l5424_bad_sd,
    l5424_sd_walked,
    l5424_escapes,
    l5424_utf8,
    roundtrip_ok,
    roundtrip_sd,
    l3164_tag,
    l3164_host,
    l3164_stamp,
    l3164_rfc3339,
    l3164_nopri,
    l3164_roundtrip,
    any_5424,
    any_3164,
    frame_octet,
    frame_trailer,
    frame_wait,
    frame_bad,
    frame_big,
};
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const alnum = "abcXYZ019-._";
const hostile = "\x00\x01\n\r\t \"\\]=[<>-:\x7f\x80\xc3\xa9\xff";

fn pick(comptime S: type, src: *S, from: []const u8) u8 {
    return from[src.index(from.len)];
}

/// `len` bytes of `from` into `w`; bytes of `hostile` now and then.
fn word(comptime S: type, src: *S, w: *std.Io.Writer, from: []const u8, max: usize, hostile_too: bool) void {
    const n: usize = src.valueRangeAtMost(u32, 1, @intCast(max));
    for (0..n) |_| {
        const b = if (hostile_too and src.valueRangeAtMost(u8, 0, 15) == 0) pick(S, src, hostile) else pick(S, src, from);
        w.writeByte(b) catch return;
    }
}

const stamps = [_][]const u8{
    "-",
    "2003-10-11T22:14:15.003Z",
    "2003-08-24T05:14:15.000003-07:00",
    "1985-04-12T23:20:50.52Z",
    "1937-01-01T12:00:27.87+00:20",
    "2000-02-29T00:00:00Z",
    "0000-01-01T00:00:00Z",
    "9999-12-31T23:59:59.999999+23:59",
};

/// A line that the grammar accepts: every field drawn from its alphabet.
fn writeValidLine(comptime S: type, src: *S, w: *std.Io.Writer) void {
    w.print("<{d}>{d} {s} ", .{ src.valueRangeAtMost(u8, 0, 191), src.valueRangeAtMost(u16, 1, 999), stamps[src.index(stamps.len)] }) catch return;
    for (0..4) |_| {
        if (src.valueRangeAtMost(u8, 0, 2) == 0) {
            w.writeByte('-') catch return;
        } else {
            word(S, src, w, alnum, 12, false);
        }
        w.writeByte(' ') catch return;
    }
    const elements = src.valueRangeAtMost(u8, 0, 3);
    if (elements == 0) w.writeByte('-') catch return;
    for (0..elements) |_| {
        w.writeByte('[') catch return;
        word(S, src, w, alnum, 10, false);
        for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
            w.writeByte(' ') catch return;
            word(S, src, w, alnum, 8, false);
            w.writeAll("=\"") catch return;
            for (0..src.valueRangeAtMost(u8, 0, 8)) |_| {
                switch (src.valueRangeAtMost(u8, 0, 7)) {
                    0 => w.writeAll("\\\"") catch return,
                    1 => w.writeAll("\\\\") catch return,
                    2 => w.writeAll("\\]") catch return,
                    3 => w.writeAll("\\q") catch return,
                    else => w.writeByte(pick(S, src, alnum)) catch return,
                }
            }
            w.writeByte('"') catch return;
        }
        w.writeByte(']') catch return;
    }
    switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => {},
        1 => w.writeAll(" \xEF\xBB\xBFtext") catch return,
        else => {
            w.writeByte(' ') catch return;
            word(S, src, w, alnum, 20, true);
        },
    }
}

fn damage(comptime S: type, src: *S, buf: []u8, len: usize) usize {
    if (len == 0) return 0;
    var n = len;
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        const at = src.index(n);
        buf[at] = if (src.valueRangeAtMost(u8, 0, 1) == 0) pick(S, src, hostile) else src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 4) == 0) n = src.index(n) + 1;
    return n;
}

fn sameOpt(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

/// What was accepted: walk everything, then the second parse must agree.
fn checkAccepted(line: []const u8, m: *const parser.Parsed) !void {
    var unesc: [4096]u8 = undefined;
    var els_store: [8]message.SdElement = undefined;
    var params_store: [8][8]message.SdParam = undefined;
    var values: [8 * 8][256]u8 = undefined;
    var n_els: usize = 0;
    var too_many = false;
    var els = m.elements();
    while (els.next()) |el| : (n_els += 1) {
        mark(.l5424_sd_walked);
        if (el.id.len == 0 or el.id.len > 32) return error.BadSdId;
        var ps = el.params();
        var n_p: usize = 0;
        while (ps.next()) |p| : (n_p += 1) {
            if (p.name.len == 0 or p.name.len > 32) return error.BadParamName;
            const v = try p.value(&unesc);
            if (v.len > p.raw_value.len) return error.UnescapeGrew;
            if (v.len != p.raw_value.len) mark(.l5424_escapes);
            if (n_els < 8 and n_p < 8 and v.len <= 256) {
                const store = values[n_els * 8 + n_p][0..v.len];
                @memcpy(store, v);
                params_store[n_els][n_p] = .{ .name = p.name, .value = store };
            } else too_many = true;
        }
        if (n_els < 8 and n_p <= 8) {
            els_store[n_els] = .{ .id = el.id, .params = params_store[n_els][0..n_p] };
        } else too_many = true;
    }
    // The walk must have consumed the whole raw field.
    if (m.structured_data) |sd| {
        var again = m.elements();
        var total: usize = 0;
        while (again.next()) |el| total += 2 + el.id.len + el.params_raw.len;
        if (total != sd.len) return error.SdWalkLost;
    }
    if (m.msg_utf8) mark(.l5424_utf8);

    // Re-encode what was read. A `-` as hostname etc. cannot come back unchanged
    // only through the timestamp's precision (the encoder's is milliseconds).
    if (too_many or n_els > 8) return;
    var out: [8192]u8 = undefined;
    const again_msg: message.Message = .{
        .facility = m.facility,
        .severity = m.severity,
        .timestamp = if (m.timestamp) |ts| ts.toTimestamp() else null,
        .hostname = m.hostname,
        .app_name = m.app_name,
        .procid = m.procid,
        .msgid = m.msgid,
        .structured_data = els_store[0..n_els],
        .msg = m.msg,
        .msg_utf8 = m.msg_utf8,
    };
    const line2 = message.bufPrint(&again_msg, &out) catch return;
    const r = parser.parse(line2) catch |e| {
        std.debug.print("re-encoded line refused ({t}):\n  {x}\n  {x}\n", .{ e, line, line2 });
        return error.ReencodedRefused;
    };
    if (r.facility != m.facility or r.severity != m.severity) return error.PriChanged;
    if (!sameOpt(r.hostname, m.hostname) or !sameOpt(r.app_name, m.app_name) or
        !sameOpt(r.procid, m.procid) or !sameOpt(r.msgid, m.msgid)) return error.HeaderChanged;
    // A MSG that is empty with a BOM loses the BOM: the encoder omits both.
    if (!std.mem.eql(u8, r.msg, m.msg)) return error.MsgChanged;
    if (m.timestamp) |ts| {
        // Before 1970 or past 9999 after the offset the encoder prints the NILVALUE.
        if (message.decompose(ts.toTimestamp())) |_| {
            const got = r.timestamp orelse return error.TimeLost;
            if (got.toTimestamp().unix_ms != ts.toTimestamp().unix_ms or got.offset_minutes != ts.offset_minutes) return error.TimeChanged;
        } else |_| if (r.timestamp != null) return error.TimeInvented;
    } else if (r.timestamp != null) return error.TimeInvented;
}

fn harness5424(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    writeValidLine(S, src, &w);
    const clean = w.buffered().len;
    const len = damage(S, src, &buf, clean);
    const line = buf[0..len];
    if (parser.parse(line)) |m| {
        mark(.l5424_ok);
        try checkAccepted(line, &m);
    } else |e| switch (e) {
        error.InvalidPriority => mark(.l5424_bad_pri),
        error.InvalidVersion => mark(.l5424_bad_version),
        error.InvalidTimestamp => mark(.l5424_bad_time),
        error.InvalidHostname, error.InvalidAppName, error.InvalidProcId, error.InvalidMsgId => mark(.l5424_bad_header),
        error.InvalidStructuredData, error.InvalidMessageStart => mark(.l5424_bad_sd),
    }
    switch (parser.parseAny(line)) {
        .rfc5424 => mark(.any_5424),
        .rfc3164 => mark(.any_3164),
    }
}

/// A field through the encoder's documented sanitizing: what `parse` must see.
fn sanitized(out: []u8, s: []const u8, max: usize) []const u8 {
    const n = @min(s.len, max);
    for (s[0..n], 0..) |b, i| out[i] = if (b >= 33 and b <= 126) b else '-';
    return out[0..n];
}

fn expectField(got: ?[]const u8, sent: ?[]const u8, max: usize) !void {
    var buf: [256]u8 = undefined;
    const s = sent orelse {
        if (got != null) return error.FieldInvented;
        return;
    };
    const want = sanitized(&buf, s, max);
    if (want.len == 0 or (want.len == 1 and want[0] == '-')) {
        if (got != null) return error.FieldInvented;
        return;
    }
    if (got == null or !std.mem.eql(u8, got.?, want)) return error.FieldChanged;
}

fn roundtripHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var fields: [5][300]u8 = undefined;
    var slices: [5]?[]const u8 = undefined;
    for (&fields, &slices, 0..) |*f, *sl, i| {
        if (src.valueRangeAtMost(u8, 0, 3) == 0) {
            sl.* = null;
            continue;
        }
        var w: std.Io.Writer = .fixed(f);
        word(S, src, &w, alnum, if (i == 0) 280 else 60, true);
        sl.* = w.buffered();
    }
    var values: [3][64]u8 = undefined;
    var params: [3]message.SdParam = undefined;
    const n_params: usize = src.valueRangeAtMost(u32, 0, 3);
    for (0..n_params) |i| {
        var w: std.Io.Writer = .fixed(&values[i]);
        word(S, src, &w, alnum, 60, true);
        params[i] = .{ .name = "k", .value = w.buffered() };
    }
    const with_sd = src.valueRangeAtMost(u8, 0, 1) == 0;
    const el: [1]message.SdElement = .{.{ .id = "id@1", .params = params[0..n_params] }};
    const ms = src.value(i64);
    const in_range = src.valueRangeAtMost(u8, 0, 7) != 0;
    const m: message.Message = .{
        .facility = @fromBackingInt(src.valueRangeAtMost(u5, 0, 23)),
        .severity = @fromBackingInt(src.valueRangeAtMost(u3, 0, 7)),
        .timestamp = if (src.valueRangeAtMost(u8, 0, 3) == 0) null else .{
            .unix_ms = if (in_range) @mod(ms, 253402300799000) else ms,
            .offset_minutes = if (src.valueRangeAtMost(u8, 0, 1) == 0) null else src.value(i16),
        },
        .hostname = slices[0],
        .app_name = slices[1],
        .procid = slices[2],
        .msgid = slices[3],
        .structured_data = if (with_sd) &el else &.{},
        .msg = slices[4] orelse "",
        .msg_utf8 = src.valueRangeAtMost(u8, 0, 3) == 0,
    };
    var out: [4096]u8 = undefined;
    const line = try message.bufPrint(&m, &out);
    const r = parser.parse(line) catch |e| {
        std.debug.print("our own line refused ({t}): {x}\n", .{ e, line });
        return e;
    };
    mark(.roundtrip_ok);
    if (r.facility != m.facility or r.severity != m.severity) return error.PriChanged;
    try expectField(r.hostname, m.hostname, message.max_hostname);
    try expectField(r.app_name, m.app_name, message.max_app_name);
    try expectField(r.procid, m.procid, message.max_procid);
    try expectField(r.msgid, m.msgid, message.max_msgid);
    if (!std.mem.eql(u8, r.msg, m.msg)) return error.MsgChanged;
    if (m.timestamp) |ts| {
        // Out of range prints the NILVALUE; in range the same instant comes back.
        if (message.decompose(ts)) |_| {
            const got = (r.timestamp orelse return error.TimeLost).toTimestamp();
            if (got.unix_ms != ts.unix_ms) {
                // An offset past ±23:59 is clamped; the instant must still hold.
                return error.TimeChanged;
            }
        } else |_| if (r.timestamp != null) return error.TimeInvented;
    }
    if (with_sd) {
        mark(.roundtrip_sd);
        var els = r.elements();
        const e0 = els.next() orelse return error.SdLost;
        var ps = e0.params();
        var unesc: [128]u8 = undefined;
        for (params[0..n_params]) |p| {
            const got = ps.next() orelse return error.ParamLost;
            if (!std.mem.eql(u8, try got.value(&unesc), p.value)) return error.ValueChanged;
        }
        if (ps.next() != null) return error.ParamInvented;
    }
}

const bsd_seeds = [_][]const u8{
    "<34>Oct 11 22:14:15 mymachine su: 'su root' failed",
    "<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!",
    "<30>Oct  1 00:00:00 sshd[42]: hi: there",
    "<14>2026-07-09T12:34:56+02:00 web-1 api[9]: ok\n",
    "<13>host more words",
    "plain text",
    "<191>Dec 31 23:59:60 a.b-c.d t.x/y-z[p]:",
};

fn bsd3164Harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const base = bsd_seeds[src.index(bsd_seeds.len)];
    @memcpy(buf[0..base.len], base);
    const len = damage(S, src, &buf, base.len);
    const line = buf[0..len];
    const r = parser.parseBsd(line);
    if (!r.has_priority) {
        mark(.l3164_nopri);
        if (!std.mem.eql(u8, r.msg, line)) return error.NoPriNotWhole;
    }
    if (r.timestamp != null) mark(.l3164_stamp);
    if (r.timestamp_rfc3339 != null) mark(.l3164_rfc3339);
    if (r.tag) |tag| {
        mark(.l3164_tag);
        if (tag.len == 0) return error.EmptyTag;
    }
    if (r.hostname) |h| {
        mark(.l3164_host);
        if (!bsd.validHostname(h)) return error.BadHostname;
    }
    // Every slice is inside the line, and MSG is its tail.
    if (r.msg.len > line.len) return error.MsgOutside;
    if (!std.mem.endsWith(u8, line, r.msg)) return error.MsgNotTail;

    // Our encoder's output reads back as sent.
    var host: [32]u8 = undefined;
    var hw: std.Io.Writer = .fixed(&host);
    word(S, src, &hw, "abc019", 12, false);
    var tag: [40]u8 = undefined;
    var tw: std.Io.Writer = .fixed(&tag);
    word(S, src, &tw, "abcXYZ019", 36, false);
    var text: [64]u8 = undefined;
    var mw: std.Io.Writer = .fixed(&text);
    word(S, src, &mw, alnum, 40, true);
    const with_pid = src.valueRangeAtMost(u8, 0, 1) == 0;
    const with_host = src.valueRangeAtMost(u8, 0, 1) == 0;
    const m: bsd.Message = .{
        .facility = @fromBackingInt(src.valueRangeAtMost(u5, 0, 23)),
        .severity = @fromBackingInt(src.valueRangeAtMost(u3, 0, 7)),
        .timestamp = .{ .unix_ms = @mod(src.value(i64), 4102444800000) },
        .hostname = if (with_host) hw.buffered() else null,
        .tag = tw.buffered(),
        .pid = if (with_pid) "123" else null,
        .msg = mw.buffered(),
    };
    var out: [512]u8 = undefined;
    const encoded = try bsd.bufPrint(&m, &out);
    const back = parser.parseBsd(encoded);
    mark(.l3164_roundtrip);
    if (back.facility != m.facility or back.severity != m.severity) return error.PriChanged;
    if (back.timestamp == null) return error.TimeLost;
    if (with_host) {
        if (back.hostname == null or !std.mem.eql(u8, back.hostname.?, m.hostname.?)) return error.HostChanged;
    } else if (back.hostname != null) return error.HostInvented;
    const want_tag = m.tag[0..@min(m.tag.len, bsd.max_tag)];
    if (back.tag == null or !std.mem.eql(u8, back.tag.?, want_tag)) return error.TagChanged;
    if (with_pid and !std.mem.eql(u8, back.pid orelse "", "123")) return error.PidChanged;
    if (!std.mem.eql(u8, back.msg, m.msg)) return error.MsgChanged;
}

fn framesHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var stream_buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&stream_buf);
    var payload_buf: [8][64]u8 = undefined;
    var payloads: [8][]const u8 = undefined;
    const n: usize = src.valueRangeAtMost(u32, 1, 8);
    for (0..n) |i| {
        var pw: std.Io.Writer = .fixed(&payload_buf[i]);
        word(S, src, &pw, alnum, 60, false);
        payloads[i] = pw.buffered();
        if (src.valueRangeAtMost(u8, 0, 1) == 0) {
            try transport.writeOctetCounted(&w, payloads[i]);
        } else {
            // A payload starting with a digit cannot be framed by a trailer.
            payload_buf[i][0] = 'x';
            try w.writeAll(payloads[i]);
            try w.writeByte(if (src.valueRangeAtMost(u8, 0, 1) == 0) '\n' else 0);
        }
    }
    const stream = w.buffered();

    // Fed in random pieces: every payload comes out, in order.
    var have: usize = 0;
    var done: usize = 0;
    var idx: usize = 0;
    while (have < stream.len or done < stream.len) {
        if (have < stream.len) have = @min(stream.len, have + @as(usize, src.valueRangeAtMost(u32, 1, 40)));
        while (try parser.nextFrame(stream[done..have], 1024)) |f| {
            if (idx >= n or !std.mem.eql(u8, f.payload, payloads[idx])) return error.FrameMismatch;
            if (f.payload.ptr == stream.ptr + done) mark(.frame_trailer) else mark(.frame_octet);
            idx += 1;
            done += f.consumed;
        }
        if (have < stream.len) mark(.frame_wait) else if (done < stream.len) return error.FrameStuck;
    }
    if (idx != n) return error.FrameLost;

    // Damaged: never more consumed than was there; an error or a wait ends it.
    const len = damage(S, src, &stream_buf, stream.len);
    var at: usize = 0;
    const limit: usize = src.valueRangeAtMost(u32, 1, 128);
    while (at < len) {
        const f = parser.nextFrame(stream_buf[at..len], limit) catch |e| {
            switch (e) {
                error.BadLength => mark(.frame_bad),
                error.FrameTooLarge => mark(.frame_big),
            }
            break;
        } orelse break;
        if (f.consumed == 0 or f.consumed > len - at or f.payload.len > limit) return error.FrameBounds;
        at += f.consumed;
    }
}

/// `testing.fuzz`'s source: every choice read by a cursor from one `slice`.
const SmithSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn value(s: *SmithSource, comptime T: type) T {
        var v: [@sizeOf(T)]u8 = undefined;
        for (&v) |*b| b.* = s.cur.byte();
        return std.mem.bytesToValue(T, &v);
    }

    pub fn valueRangeAtMost(s: *SmithSource, comptime T: type, lo: T, hi: T) T {
        return @intCast(s.cur.ranged(@intCast(lo), @intCast(hi)));
    }

    pub fn index(s: *SmithSource, len: usize) usize {
        return s.cur.ranged(0, @intCast(len - 1));
    }
};

fn fuzzScript(comptime harness: anytype) fn (void, *testing.Smith) anyerror!void {
    return struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [2048]u8 = undefined;
            const n = smith.slice(&buf);
            var src: SmithSource = .{ .cur = .{ .bytes = buf[0..n] } };
            return harness(SmithSource, &src, testing.allocator);
        }
    }.run;
}

test "testing.fuzz: 5424" {
    try testing.fuzz({}, fuzzScript(harness5424), .{});
}

test "testing.fuzz: roundtrip" {
    try testing.fuzz({}, fuzzScript(roundtripHarness), .{});
}

test "testing.fuzz: 3164" {
    try testing.fuzz({}, fuzzScript(bsd3164Harness), .{});
}

test "testing.fuzz: frames" {
    try testing.fuzz({}, fuzzScript(framesHarness), .{});
}

test "fuzz driver: SYSLOG_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ harness5424, .{ .prefix = "SYSLOG_FUZZ", .name = "syslog-5424" } },
        .{ roundtripHarness, .{ .prefix = "SYSLOG_FUZZ", .name = "syslog-roundtrip" } },
        .{ bsd3164Harness, .{ .prefix = "SYSLOG_FUZZ", .name = "syslog-3164" } },
        .{ framesHarness, .{ .prefix = "SYSLOG_FUZZ", .name = "syslog-frames" } },
    });
}

test "fuzz harness: 3000 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..3000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        try harness5424(fuzz_driver.Rng, &rng, testing.allocator);
        try roundtripHarness(fuzz_driver.Rng, &rng, testing.allocator);
        try bsd3164Harness(fuzz_driver.Rng, &rng, testing.allocator);
        try framesHarness(fuzz_driver.Rng, &rng, testing.allocator);
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 3000 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
