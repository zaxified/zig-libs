// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for aeadframe (added 2026-10-10): `AEADFRAME_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `aeadframe-channel` (both AEADs: a Sealer feeds an Opener with records
//! delivered in a drawn order with duplicates; the result of every delivery
//! equals an independent replay model; before each delivery a flipped bit, a
//! truncation, other associated data and an undersized output buffer are
//! refused and change nothing; an epoch bump refuses the old epoch's records;
//! a sequence at the top of u64 is exhausted, never wrapped) and
//! `aeadframe-record` (`record.parse` on damaged records: accepted means the
//! header re-encodes to the input's first octets).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
pub const Cursor = testkit.fuzz.Cursor;

/// Reach counters for one harness's labels. `mark` also feeds the driver's
/// `REACH` report; `reach` runs `seeds` seeds in the ordinary test binary and
/// fails with `error.HarnessDoesNotReach` if a label never fired.
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

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated.
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

/// Deterministic bytes from a knob cursor (its first octets seed a PRNG).
pub fn expand(knobs: *Cursor, out: []u8) void {
    var s: u64 = 0;
    for (0..8) |_| s = (s << 8) | knobs.byte();
    var prng = std.Random.DefaultPrng.init(s);
    prng.random().bytes(out);
}

/// Smith-side wrapper so `--fuzz` keeps working: the harness bodies are
/// generic over `S`; `testing.fuzz` hands them a `std.testing.Smith`.
pub fn smithWrap(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

const aeadframe = @import("root.zig");
const record = @import("record.zig");

fn flipBit(knobs: *Cursor, bytes: []u8) void {
    const at = (@as(usize, knobs.byte()) << 8 | knobs.byte()) % bytes.len;
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
}

const ChanMark = Marker(enum {
    accepted,
    replay_refused,
    window_refused,
    reordered_accepted,
    flipped_refused,
    truncated_refused,
    wrong_aad_refused,
    small_out_refused,
    old_epoch_refused,
    new_epoch_accepted,
    exhausted,
    chacha,
    aes_gcm,
});

fn Run(comptime C: type) type {
    return struct {
        fn go(knobs: *Cursor, src: anytype) !void {
            var key: [32]u8 = undefined;
            expand(knobs, &key);
            const epoch: u32 = knobs.byte();
            var s = C.Sealer.init(key, epoch);
            const wsizes = [_]u7{ 0, 1, 4, 64, 127 };
            const wsize = wsizes[knobs.ranged(0, wsizes.len - 1)];
            var o = C.Opener.initWindow(key, epoch, wsize);
            const eff: u64 = @min(wsize, 64);

            const n = knobs.ranged(2, 12);
            var recs: [12][record.overhead + 20]u8 = undefined;
            var rlen: [12]usize = undefined;
            var pts: [12][20]u8 = undefined;
            var plen: [12]usize = undefined;
            var aads: [12][8]u8 = undefined;
            var alen: [12]usize = undefined;
            for (0..n) |i| {
                expand(knobs, &pts[i]);
                plen[i] = knobs.ranged(0, 20);
                expand(knobs, &aads[i]);
                alen[i] = knobs.ranged(0, 8);
                rlen[i] = try s.seal(&recs[i], pts[i][0..plen[i]], aads[i][0..alen[i]]);
            }

            var seen: [12]bool = @splat(false);
            var started = false;
            var hi: usize = 0;
            const deliveries = knobs.ranged(1, 16);
            var max_idx_delivered: ?usize = null;
            for (0..deliveries) |_| {
                const i = knobs.ranged(0, @intCast(n - 1));
                const rec = recs[i][0..rlen[i]];
                const aad = aads[i][0..alen[i]];
                var out: [20]u8 = undefined;
                // Damaged attempts first: refused, state untouched.
                {
                    var bad = recs[i];
                    flipBit(knobs, bad[0..rlen[i]]);
                    if (o.open(&out, bad[0..rlen[i]], aad)) |_| return error.FlippedRecordAccepted else |_| ChanMark.mark(.flipped_refused);
                    const cut = knobs.ranged(0, @intCast(rlen[i] - 1));
                    if (o.open(&out, rec[0..cut], aad)) |_| return error.TruncatedRecordAccepted else |_| ChanMark.mark(.truncated_refused);
                    var aad2: [9]u8 = undefined;
                    @memcpy(aad2[0..aad.len], aad);
                    aad2[aad.len] = 0x55;
                    if (o.open(&out, rec, aad2[0 .. aad.len + 1])) |_| return error.WrongAadAccepted else |_| ChanMark.mark(.wrong_aad_refused);
                    if (plen[i] > 0) {
                        if (o.open(out[0 .. plen[i] - 1], rec, aad)) |_| return error.SmallBufferAccepted else |_| ChanMark.mark(.small_out_refused);
                    }
                    var buf: [record.overhead + 24]u8 = undefined;
                    const dn = damage(src, &buf, rec);
                    if (!std.mem.eql(u8, buf[0..dn], rec)) {
                        if (o.open(&out, buf[0..dn], aad)) |_| return error.DamagedRecordAccepted else |_| {}
                    }
                }
                const expect_ok = !seen[i] and (!started or i > hi or (hi - i) <= eff and i != hi);
                if (o.open(&out, rec, aad)) |m| {
                    if (!expect_ok) return error.ModelRefusesButOpenerAccepts;
                    if (m != plen[i] or !std.mem.eql(u8, out[0..m], pts[i][0..plen[i]])) return error.PlaintextDiffers;
                    ChanMark.mark(.accepted);
                    if (started and i < hi) ChanMark.mark(.reordered_accepted);
                    seen[i] = true;
                    if (!started or i > hi) hi = i;
                    started = true;
                    max_idx_delivered = i;
                } else |e| {
                    if (expect_ok) return error.ModelAcceptsButOpenerRefuses;
                    if (seen[i]) ChanMark.mark(.replay_refused) else {
                        if (e != error.Replayed) return error.WrongRefusalKind;
                        ChanMark.mark(.window_refused);
                    }
                }
            }

            // Epoch bump: the old epoch's records are refused, the new one's accepted.
            try s.bumpEpoch();
            try o.bumpEpoch();
            var out: [20]u8 = undefined;
            if (o.open(&out, recs[0][0..rlen[0]], aads[0][0..alen[0]])) |_| return error.OldEpochAccepted else |e| {
                if (e != error.EpochMismatch) return error.WrongRefusalKind;
                ChanMark.mark(.old_epoch_refused);
            }
            var r2: [record.overhead + 4]u8 = undefined;
            const l2 = try s.seal(&r2, "next", "");
            const m2 = o.open(&out, r2[0..l2], "") catch return error.NewEpochRefused;
            if (!std.mem.eql(u8, out[0..m2], "next")) return error.PlaintextDiffers;
            ChanMark.mark(.new_epoch_accepted);

            // The top of the sequence space is exhausted, never wrapped.
            s.seq = std.math.maxInt(u64) - 1;
            _ = try s.seal(&r2, "last", "");
            if (s.seal(&r2, "more", "")) |_| return error.SequenceWrapped else |e| {
                if (e != error.SequenceExhausted) return error.WrongRefusalKind;
                ChanMark.mark(.exhausted);
            }
        }
    };
}

fn fuzzChannel(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [32]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    if (knobs.byte() & 1 == 0) {
        ChanMark.mark(.chacha);
        try Run(aeadframe.ChaChaChannel).go(&knobs, src);
    } else {
        ChanMark.mark(.aes_gcm);
        try Run(aeadframe.AesGcmChannel).go(&knobs, src);
    }
}

test "fuzz: aeadframe channel matches the replay model, damage refused" {
    try testing.fuzz({}, smithWrap(fuzzChannel), .{});
}
test "fuzz driver: AEADFRAME_FUZZ (channel)" {
    try fuzz_driver.run(fuzzChannel, .{ .prefix = "AEADFRAME_FUZZ", .name = "aeadframe-channel" });
}
test "fuzz harness: channel, 400 seeds, reaches every outcome" {
    try ChanMark.reach(fuzzChannel, "aeadframe-channel", 400);
}

const RecMark = Marker(enum { parsed, truncated, unsupported_version });

fn fuzzRecord(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [8]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var key: [32]u8 = undefined;
    expand(&knobs, &key);
    var s = aeadframe.ChaChaChannel.Sealer.init(key, knobs.byte());
    var rec: [record.overhead + 10]u8 = undefined;
    const l = try s.seal(&rec, "0123456789"[0..knobs.ranged(0, 10)], "");
    var buf: [record.overhead + 16]u8 = undefined;
    const n = damage(src, &buf, rec[0..l]);
    if (record.parse(buf[0..n])) |p| {
        var h: [record.header_len]u8 = undefined;
        p.header.encode(&h);
        if (!std.mem.eql(u8, &h, buf[0..record.header_len])) return error.HeaderDoesNotReencode;
        if (p.ct_off + p.ct_len + record.tag_len != n) return error.LengthsInconsistent;
        RecMark.mark(.parsed);
    } else |e| switch (e) {
        error.Truncated => RecMark.mark(.truncated),
        error.UnsupportedVersion => RecMark.mark(.unsupported_version),
    }
}

test "fuzz: aeadframe record parse" {
    try testing.fuzz({}, smithWrap(fuzzRecord), .{});
}
test "fuzz driver: AEADFRAME_FUZZ (record)" {
    try fuzz_driver.run(fuzzRecord, .{ .prefix = "AEADFRAME_FUZZ", .name = "aeadframe-record" });
}
test "fuzz harness: record, 600 seeds, reaches every outcome" {
    try RecMark.reach(fuzzRecord, "aeadframe-record", 600);
}
