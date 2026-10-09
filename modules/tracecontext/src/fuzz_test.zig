// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over tracecontext's existing `testing.fuzz`
//! harness (`TraceParent.parse` on arbitrary or traceparent-shaped bytes,
//! added 2026-10-09). The body lives here, generic over its source of choices
//! (`fn(comptime S, *S, gpa)`); `root.zig`'s `testing.fuzz` test feeds it
//! through the cursor adapter below, the driver feeds it a PRNG.
//!
//! Reach: the shaped path picks ONE fault per field (wrong length, an
//! uppercase digit, an arbitrary octet) with probability 1/4 and otherwise
//! writes clean lowercase hex, so about a quarter of shaped inputs are valid
//! headers and `accepted` is a label. (A per-octet fault needed ~50 clean
//! digits in a row and never produced one under the driver: measured
//! 2026-10-09, 0 accepted in 200k runs.)
//!
//! Driver: `TRACECONTEXT_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `_MS`, `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const tracecontext = @import("root.zig");

pub const Label = enum { verbatim, shaped, header_length, rejected, accepted };
var reach: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and
/// every choice is read from them by a cursor -- so each seed is its own input.
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

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

const hex_digits = "0123456789abcdef";

/// The header buffer, plus one octet of mode. `header_len` is 55 and the
/// longest corpus seed is the extension one at 68, so 128 is not tight.
pub const traceparent_buf_len = 128;

/// `TraceParent.parse` never panics on arbitrary or traceparent-shaped bytes.
pub fn parseHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var raw: [1 + traceparent_buf_len]u8 = undefined;
    const n: usize = src.slice(&raw);
    var buf: [traceparent_buf_len]u8 = undefined;
    const input = buildTraceparent(raw[0..n], &buf);
    if (n != 0) {
        if (raw[0] == 0) mark(.verbatim) else mark(.shaped);
    }
    if (input.len == tracecontext.TraceParent.header_len) mark(.header_length);
    _ = tracecontext.TraceParent.parse(input) catch {
        mark(.rejected);
        return;
    };
    mark(.accepted);
}

/// Octet 0 selects: `0x00` means the remaining octets are the header
/// verbatim; anything else means they are a script assembling
/// `version-traceid-parentid-flags` field by field, each field independently
/// its nominal length or off by one, carrying at most one bad octet, and
/// each delimiter usually `-` but sometimes not.
pub fn buildTraceparent(seed: []const u8, buf: []u8) []const u8 {
    if (seed.len == 0) return buf[0..0];
    if (seed[0] == 0) {
        const body = seed[1..];
        const n = @min(body.len, buf.len);
        @memcpy(buf[0..n], body[0..n]);
        return buf[0..n];
    }
    var script: testkit.fuzz.Cursor = .{ .bytes = seed[1..] };
    var w: std.Io.Writer = .fixed(buf);
    writeField(&script, &w, 2); // version
    writeDelim(&script, &w);
    writeField(&script, &w, 32); // trace-id
    writeDelim(&script, &w);
    writeField(&script, &w, 16); // parent-id
    writeDelim(&script, &w);
    writeField(&script, &w, 2); // flags
    // Occasionally a trailing extension, as a future version may carry.
    if (script.byte() & 1 == 1) {
        w.writeByte('-') catch return w.buffered();
        writeField(&script, &w, @intCast(script.ranged(0, 12)));
    }
    return w.buffered();
}

fn writeDelim(script: *testkit.fuzz.Cursor, w: *std.Io.Writer) void {
    const c: u8 = if (script.ranged(0, 15) == 0) '_' else '-';
    w.writeByte(c) catch {};
}

/// One fault per field at most, chosen up front: 0 short, 1 long, 2 one
/// uppercase digit (invalid per spec — lowercase is mandated), 3 one
/// arbitrary octet, anything else clean lowercase hex.
fn writeField(script: *testkit.fuzz.Cursor, w: *std.Io.Writer, nominal_len: u8) void {
    const fault = script.ranged(0, 15);
    const delta: i16 = switch (fault) {
        0 => -1,
        1 => 1,
        else => 0,
    };
    const len: u8 = @intCast(std.math.clamp(@as(i16, nominal_len) + delta, 0, 48));
    const bad_at = if (len == 0) 0 else script.ranged(0, len - 1);
    var i: u8 = 0;
    while (i < len) : (i += 1) {
        var c = hex_digits[script.byte() & 0xf];
        if (i == bad_at) switch (fault) {
            2 => c = std.ascii.toUpper(c),
            3 => c = script.byte(),
            else => {},
        };
        w.writeByte(c) catch return;
    }
}

test "fuzz driver: TRACECONTEXT_FUZZ" {
    try fuzz_driver.run(parseHarness, .{ .prefix = "TRACECONTEXT_FUZZ", .name = "tracecontext" });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        parseHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("tracecontext seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
