// SPDX-License-Identifier: MIT

//! Shared plumbing for pbb's deterministic fuzz driver (added 2026-10-10).
//!
//! The decode harness body stays in `root.zig` beside its corpus, generic over
//! its source of choices, `fn(comptime S, *S, gpa)`; `testing.fuzz` hands it a
//! `std.testing.Smith` (corpus seeds replay as before). This file holds what it
//! shares with the driver -- reach counters, the input draw -- and the
//! encode/decode oracle: a frame this module issued decodes to the fields and
//! customer data it was built from, any shorter prefix that still holds the
//! header decodes to the matching customer prefix, and a prefix cut inside the
//! header is refused.
//!
//! Driver: `PBB_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness). Harness names: `pbb-decode`, `pbb-roundtrip`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
const pbb = @import("root.zig");

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the bend words after the frame are dropped) with 0-3 octets
/// damaged and maybe truncated: random text almost never passes the checksum.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
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

// ── oracle ───────────────────────────────────────────────────────────────

const Mark = Marker(enum { tagged, untagged, genuine_accepted, prefix_accepted, header_cut_refused });

fn mac(src: anytype) pbb.Mac {
    var m: pbb.Mac = undefined;
    src.bytes(&m);
    return m;
}

fn fuzzRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const f: pbb.Fields = .{
        .b_da = mac(src),
        .b_sa = mac(src),
        .b_tag = if (src.value(bool)) .{ .pcp = src.value(u3), .dei = src.value(bool), .vid = src.value(u12) } else null,
        .i_pcp = src.value(u3),
        .i_dei = src.value(bool),
        .uca = src.value(bool),
        .i_sid = src.value(u24),
        .c_da = mac(src),
        .c_sa = mac(src),
    };
    if (f.b_tag == null) Mark.mark(.untagged) else Mark.mark(.tagged);
    var data: [200]u8 = undefined;
    const n: usize = if (src.value(bool)) src.index(8) else src.index(data.len + 1);
    src.bytes(data[0..n]);
    var out: [pbb.min_frame_len + pbb.b_tag_len + 200]u8 = undefined;
    const frame = try pbb.encode(f, data[0..n], &out);

    const d = pbb.decode(frame) catch return error.GenuineRefused;
    if (!std.meta.eql(d.fields, f) or !std.mem.eql(u8, d.customer_data, data[0..n])) return error.RoundtripMismatch;
    Mark.mark(.genuine_accepted);

    const hdr = pbb.headerLen(f.b_tag != null);
    const cut = src.index(frame.len);
    if (cut >= hdr) {
        // The remaining header bytes decide whether a cut frame still reads as
        // the same shape; a B-Tagged frame cut anywhere past its header is
        // still that frame.
        const dd = pbb.decode(frame[0..cut]) catch return error.PrefixRefused;
        if (!std.meta.eql(dd.fields, f) or !std.mem.eql(u8, dd.customer_data, data[0 .. cut - hdr])) return error.PrefixMismatch;
        Mark.mark(.prefix_accepted);
    } else {
        // Cut inside the header: an untagged frame can never decode; a tagged
        // one cut to the untagged length would have to re-read as untagged,
        // which its 0x88A8 EtherType rules out.
        if (pbb.decode(frame[0..cut])) |_| return error.HeaderCutAccepted else |_| {}
        Mark.mark(.header_cut_refused);
    }
}

test "fuzz driver: PBB_FUZZ (roundtrip)" {
    try fuzz_driver.run(fuzzRoundtrip, .{ .prefix = "PBB_FUZZ", .name = "pbb-roundtrip" });
}

test "fuzz harness: roundtrip, 400 seeds, reaches every outcome" {
    try Mark.reach(fuzzRoundtrip, "pbb-roundtrip", 400);
}

fn roundtripSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzRoundtrip(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: roundtrip, exploration" {
    try testing.fuzz({}, roundtripSmith, .{});
}
