// SPDX-License-Identifier: MIT

//! Shared plumbing for threshold_ecdsa's deterministic fuzz driver (added
//! 2026-10-10, the jwt pattern). The harness BODIES stay beside their corpora in
//! `root.zig`, `zkproofs.zig`, `aux_proofs.zig`, `ecproofs.zig` and
//! `presign.zig`; each is generic over its source of choices
//! (`fn(comptime S, *S, gpa)`), `testing.fuzz` hands it a `std.testing.Smith`
//! (one `slice` first, so corpus seeds replay as before), the driver a PRNG.
//!
//! Driver: `TECDSA_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `tecdsa-feldman`, `tecdsa-public-keys`,
//! `tecdsa-aux-params`, `tecdsa-key-share`, `tecdsa-element`,
//! `tecdsa-ec-proofs`, `tecdsa-range-proof`, `tecdsa-mta-proof`,
//! `tecdsa-mta-proof-wc`, `tecdsa-mod-proof`, `tecdsa-prm-proof`,
//! `tecdsa-pdl-proof`, `tecdsa-fac-proof`, `tecdsa-presig`, `tecdsa-combine`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// What one draw produced.
pub const Draw = struct {
    len: usize,
    /// Index of the corpus entry the draw started from, null for a plain slice.
    entry: ?usize = null,
    /// True when the corpus frame was damaged or truncated.
    damaged: bool = false,
};

/// One harness input into `buf`. Under `Smith` (`--fuzz`, `_INPUT` replay) it
/// is exactly `src.slice`. Under the driver's `Rng` half the draws are a corpus
/// entry (frames carry a little-endian u32 length header) with 0-3 octets
/// damaged and maybe truncated, a quarter of them intact; the rest is a plain
/// slice. Random bytes alone almost never get past the first length check.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) Draw {
    if (S != fuzz_driver.Rng) return .{ .len = src.slice(buf) };
    if (corpus.len == 0 or !src.value(bool)) return .{ .len = src.slice(buf) };
    const idx = src.index(corpus.len);
    const entry = corpus[idx];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    var damaged = n != frame.len;
    if (src.valueRangeAtMost(u8, 0, 3) != 0) {
        for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
            if (n == 0) break;
            buf[src.index(n)] = src.value(u8);
            damaged = true;
        }
        if (src.valueRangeAtMost(u8, 0, 3) == 0) {
            n = src.index(n + 1);
            damaged = true;
        }
    }
    return .{ .len = n, .entry = idx, .damaged = damaged };
}

/// Shape of a `drawFields` frame beyond its flat list of fields.
pub const Shape = struct {
    /// The field count of the decoder's own layout (0: none), used for 3/4 of
    /// the draws.
    want: u8 = 0,
    /// The fields form a length-prefixed inner frame (u32 big-endian)...
    wrap: bool = false,
    /// ...followed by this many octets of a curve point (a valid one unless
    /// damaged).
    tail: ?[33]u8 = null,
};

/// Random frame of length-prefixed (u32 big-endian) fields, the lengths
/// sometimes lying and the content mostly SMALL values (zero octets and a
/// low one: field elements of the toy moduli the decoders are fixtured with),
/// the shape every decoder here parses first. Returns the length written.
pub fn drawFields(comptime S: type, src: *S, buf: []u8, shape: Shape) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    const head: usize = if (shape.wrap) 4 else 0;
    const tail_len: usize = if (shape.tail != null) 33 else 0;
    var n: usize = head;
    const limit = buf.len - tail_len;
    const count = if (shape.want != 0 and src.valueRangeAtMost(u8, 0, 3) != 0) shape.want else src.valueRangeAtMost(u8, 0, 14);
    for (0..count) |_| {
        if (n + 4 > limit) break;
        const room = limit - n - 4;
        var flen: usize = switch (src.valueRangeAtMost(u8, 0, 5)) {
            0 => 0,
            1 => 1,
            2 => src.index(@min(room, 40) + 1),
            else => src.index(@min(room, 300) + 1),
        };
        flen = @min(flen, room);
        const declared: u32 = if (src.valueRangeAtMost(u8, 0, 11) == 0) src.value(u32) else @intCast(flen);
        std.mem.writeInt(u32, buf[n..][0..4], declared, .big);
        n += 4;
        if (src.valueRangeAtMost(u8, 0, 2) != 0 and flen != 0) {
            @memset(buf[n..][0..flen], 0);
            buf[n + flen - 1] = src.valueRangeAtMost(u8, 0, 127);
        } else src.bytes(buf[n..][0..flen]);
        n += flen;
    }
    if (shape.wrap) {
        const inner: u32 = if (src.valueRangeAtMost(u8, 0, 11) == 0) src.value(u32) else @intCast(n - 4);
        std.mem.writeInt(u32, buf[0..4], inner, .big);
    }
    if (shape.tail) |t| {
        buf[n..][0..33].* = t;
        if (src.valueRangeAtMost(u8, 0, 7) == 0) buf[n + src.index(33)] = src.value(u8);
        n += 33;
    }
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn count(l: Label) usize {
            return counts[@intFromEnum(l)];
        }

        pub fn reset() void {
            counts = @splat(0);
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
