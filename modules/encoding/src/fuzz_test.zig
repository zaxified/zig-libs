// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over encoding's existing `testing.fuzz` harness
//! (`decodeToUtf8` / `encodeFromUtf8` over every table, added 2026-10-09). The
//! body lives here, generic over its source of choices (`fn(comptime S, *S,
//! gpa)`); `root.zig`'s `testing.fuzz` test feeds it through the cursor adapter
//! below, the driver feeds it a PRNG. Both codecs are lenient by design (they
//! never fail), so the reach labels describe the INPUT classes got through.
//!
//! Driver: `ENCODING_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const encoding = @import("root.zig");
const core = @import("core.zig");

pub const Label = enum { nonempty, high_bytes, replacement, round_trip };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
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

/// Every encoding (the passthrough and all 29 single-byte pages).
const encodings = blk: {
    const vals = @typeInfo(encoding.Encoding).@"enum".field_values;
    var out: [vals.len]encoding.Encoding = undefined;
    for (vals, 0..) |v, i| out[i] = @fromBackingInt(@intCast(v));
    const final = out;
    break :blk final;
};

/// Neither codec panics, goes out of bounds or leaks on arbitrary bytes, in
/// every encoding, both directions; and the caller-buffer core gives the
/// whole-buffer answer for any cut and any output room, byte-by-byte input
/// included (which drives the UTF decoders' state machines alone, so it
/// checks the fast paths against them).
pub fn codecHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [256]u8 = undefined;
    const len = src.slice(&buf);
    if (len < 2) return;
    const sel = buf[0];
    const room_sel = buf[1];
    const input = buf[2..len];
    if (input.len != 0) mark(.nonempty);
    if (std.mem.findAny(u8, input, &[_]u8{ 0x80, 0xC3, 0xFF }) != null) mark(.high_bytes);
    try testing.expectEqual(std.unicode.utf8ValidateSlice(input), core.validUtf8(input));

    const e = encodings[sel % encodings.len];
    const kind: encoding.Decoder.Kind = if (sel & 0x80 != 0) .{ .utf16 = if (sel & 0x40 != 0) .le else .be } else .{ .encoding = e };
    const whole = switch (kind) {
        .encoding => |x| try encoding.decodeToUtf8(gpa, input, x),
        .utf16 => |x| try encoding.decodeUtf16(gpa, input, x),
    };
    defer gpa.free(whole);
    try testing.expect(std.unicode.utf8ValidateSlice(whole));
    if (std.mem.find(u8, whole, "\xEF\xBF\xBD") != null) mark(.replacement);

    const room = 7 + room_sel % 24;
    const cut = if (input.len == 0) 0 else room_sel % (input.len + 1);
    const pieces = try decodePieces(gpa, kind, input, room, cut);
    defer gpa.free(pieces);
    try testing.expectEqualStrings(whole, pieces);
    var d: encoding.Decoder = .init(kind, .{});
    var bytewise: std.ArrayList(u8) = .empty;
    defer bytewise.deinit(gpa);
    for (input) |b| try d.feed(gpa, &bytewise, &.{b});
    try d.finish(gpa, &bytewise);
    try testing.expectEqualStrings(whole, bytewise.items);

    // Encode the input (arbitrary bytes, as UTF-8) the same three ways.
    const ekind: encoding.Encoder.Kind = switch (kind) {
        .encoding => |x| .{ .encoding = x },
        .utf16 => |x| .{ .utf16 = x },
    };
    const mode: encoding.Unmappable = switch (room_sel % 3) {
        0 => .question_mark,
        1 => .html_ncr,
        else => .ignore,
    };
    var ew: encoding.Encoder = .init(ekind, .{ .unmappable = mode });
    var ewhole: std.ArrayList(u8) = .empty;
    defer ewhole.deinit(gpa);
    try ew.feed(gpa, &ewhole, input);
    try ew.finish(gpa, &ewhole);
    var eb: encoding.Encoder = .init(ekind, .{ .unmappable = mode });
    var ebyte: std.ArrayList(u8) = .empty;
    defer ebyte.deinit(gpa);
    for (input) |b| try eb.feed(gpa, &ebyte, &.{b});
    try eb.finish(gpa, &ebyte);
    try testing.expectEqualSlices(u8, ewhole.items, ebyte.items);
    if (kind == .encoding and e != .utf8 and std.unicode.utf8ValidateSlice(input)) {
        // Valid text round-trips except where the page lacks a character.
        const legacy = try encoding.encodeFromUtf8(gpa, input, e);
        defer gpa.free(legacy);
        const back = try encoding.decodeToUtf8(gpa, legacy, e);
        defer gpa.free(back);
        if (std.mem.findScalar(u8, legacy, '?') == null) {
            try testing.expectEqualStrings(input, back);
            mark(.round_trip);
        }
    }
}

fn decodePieces(a: std.mem.Allocator, kind: encoding.Decoder.Kind, input: []const u8, room: usize, cut: usize) ![]u8 {
    var d: encoding.Decoder = .init(kind, .{});
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    const parts = [2][]const u8{ input[0..cut], input[cut..] };
    for (parts, 0..) |part, pi| {
        var r: usize = 0;
        while (true) {
            var tmp: [32]u8 = undefined;
            const p = d.decodeInto(part[r..], tmp[0..room], pi == 1);
            try out.appendSlice(a, tmp[0..p.written]);
            r += p.read;
            if (p.status == .input_empty) break;
        }
    }
    return out.toOwnedSlice(a);
}

test "fuzz driver: ENCODING_FUZZ" {
    try fuzz_driver.run(codecHarness, .{ .prefix = "ENCODING_FUZZ", .name = "encoding" });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        codecHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("encoding seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
