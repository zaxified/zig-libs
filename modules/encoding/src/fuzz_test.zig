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

pub const Label = enum { nonempty, high_bytes, replacement };
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

/// The encodings the harness sweeps (the passthrough and the five tables).
const encodings = [_]encoding.Encoding{ .utf8, .windows_1250, .windows_1252, .iso_8859_1, .iso_8859_2, .iso_8859_15 };

/// Neither codec panics, goes out of bounds or leaks on arbitrary bytes, in
/// every encoding, both directions.
pub fn codecHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [256]u8 = undefined;
    const len = src.slice(&buf);
    const input = buf[0..len];
    if (len != 0) mark(.nonempty);
    if (std.mem.indexOfAny(u8, input, &[_]u8{ 0x80, 0xC3, 0xFF }) != null) mark(.high_bytes);
    for (encodings) |enc| {
        const decoded = try encoding.decodeToUtf8(gpa, input, enc);
        defer gpa.free(decoded);
        if (enc == .utf8 and std.mem.indexOf(u8, decoded, "\xEF\xBF\xBD") != null) mark(.replacement);
        const encoded = try encoding.encodeFromUtf8(gpa, input, enc);
        defer gpa.free(encoded);
    }
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
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
