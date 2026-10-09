// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over json5's two existing `testing.fuzz`
//! harnesses (`preprocess`, `preprocessAnnotated`; added 2026-10-09). The
//! bodies live here, generic over their source of choices
//! (`fn(comptime S, *S, gpa)`); `root.zig`'s `testing.fuzz` tests feed them
//! through the cursor adapter below, the driver feeds them a PRNG.
//!
//! Driver: `JSON5_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const json5 = @import("root.zig");

pub const Label = enum { accepted, changed, compared };
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

pub fn jsonParses(alloc: std.mem.Allocator, text: []const u8) bool {
    const parsed = std.json.parseFromSlice(std.json.Value, alloc, text, .{
        .duplicate_field_behavior = .use_last,
    }) catch return false;
    parsed.deinit();
    return true;
}

/// `preprocess` must never panic or leak on arbitrary bytes.
pub fn preprocessHarness(comptime S: type, src: *S, alloc: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = src.slice(&buf);
    const out = json5.preprocess(alloc, buf[0..len]) catch return; // `refused` is not reachable from random bytes (400 seeds: 0 hits)
    defer alloc.free(out);
    mark(.accepted);
    if (!std.mem.eql(u8, out, buf[0..len])) mark(.changed);
}

/// `preprocessAnnotated` never panics, and agrees with `preprocess` on whether
/// the result parses as JSON (turning diagnostics on must not change that).
pub fn annotatedHarness(comptime S: type, src: *S, alloc: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = src.slice(&buf);
    const input = buf[0..len];
    const r = json5.preprocessAnnotated(alloc, input) catch return;
    defer alloc.free(r.out);
    const plain = json5.preprocess(alloc, input) catch return;
    defer alloc.free(plain);
    const ann_ok = jsonParses(alloc, r.out);
    const plain_ok = jsonParses(alloc, plain);
    // (`ann_ok` itself is not a label: random bytes are almost never JSON.)
    mark(.compared);
    if (ann_ok != plain_ok) {
        std.debug.print(
            "\nentry points disagree on {f}\n  preprocess ({}): {f}\n  annotated  ({}): {f}\n",
            .{
                std.ascii.hexEscape(input, .lower),
                plain_ok,
                std.ascii.hexEscape(plain, .lower),
                ann_ok,
                std.ascii.hexEscape(r.out, .lower),
            },
        );
        return error.EntryPointsDisagree;
    }
}

test "fuzz driver: JSON5_FUZZ" {
    try fuzz_driver.run(preprocessHarness, .{ .prefix = "JSON5_FUZZ", .name = "json5-preprocess" });
    try fuzz_driver.run(annotatedHarness, .{ .prefix = "JSON5_FUZZ", .name = "json5-annotated" });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        preprocessHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("json5 preprocess seed {d}: {t}\n", .{ seed, err });
            return err;
        };
        annotatedHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("json5 annotated seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}
