// SPDX-License-Identifier: MIT

//! Gorilla-style compressed sample block codec.
//!
//! Implements the timestamp (delta-of-delta) and value (XOR) compression of
//! Pelkonen et al., "Gorilla: A Fast, Scalable, In-Memory Time Series
//! Database", VLDB 2015, section 4.1, as a pure, allocation-free block format:
//! a `Writer` packs strictly ascending samples into one fixed-capacity block
//! of at most `max_block_bytes`, a `Reader` unpacks it lazily.
//!
//! Block layout (all bit fields MSB-first, the stream zero-padded to a byte):
//!
//!     u16 BE count                    (>= 1)
//!     sample 0:  ts (64 raw bits), value (64 raw bits)
//!     sample i:  timestamp record, value record
//!
//! Timestamp record, `dod = (ts_i - ts_{i-1}) - prev_delta` in wrapping i64
//! arithmetic (`prev_delta = 0` for i == 1), stored in an N-bit two's
//! complement field with exact N-bit ranges:
//!
//!     '0'                       dod == 0
//!     '10'   + 7 bits           -64   ..= 63
//!     '110'  + 9 bits           -256  ..= 255
//!     '1110' + 12 bits          -2048 ..= 2047
//!     '1111' + 64 bits          anything else
//!
//! Value record, `x = bits(v_i) ^ bits(v_{i-1})`:
//!
//!     '0'                       x == 0
//!     '1' '0' + prev_sig bits   x fits the previous window
//!     '1' '1' + 5 bits lz + 6 bits (sig-1) + sig bits   new window
//!
//! `lz` is clamped to 31 before `sig = 64 - lz - tz` is derived, so `sig` is
//! always 1..=64. Values are opaque bits: NaN payloads, -0.0 and infinities
//! round-trip bit-exactly.

const std = @import("std");

/// One time series sample. `value` is stored as its raw bit pattern.
pub const Sample = struct { ts: i64, value: f64 };

/// Encoded size cap of a block, including the 2-byte count header.
pub const max_block_bytes: usize = 1024;
/// Sample count cap of a block.
pub const max_block_samples: u16 = 1024;

const header_bytes: usize = 2;
const first_sample_bits: usize = 128;

/// Appends the low `n` bits (0..=64) of `v` to `stream` at bit position
/// `pos.*`, MSB-first. Only ORs, so the target must be zero beforehand.
fn putBits(stream: []u8, pos: *usize, v: u64, n: u8) void {
    var remaining: u8 = n;
    while (remaining > 0) {
        const idx = pos.* / 8;
        const avail: u8 = 8 - @as(u8, @intCast(pos.* % 8));
        const take: u8 = @min(avail, remaining);
        const shift: u6 = @intCast(remaining - take);
        const mask: u8 = @truncate((@as(u16, 1) << @intCast(take)) - 1);
        const chunk: u8 = @as(u8, @truncate(v >> shift)) & mask;
        stream[idx] |= chunk << @as(u3, @intCast(avail - take));
        pos.* += take;
        remaining -= take;
    }
}

/// Reads `n` bits (0..=64) at `pos.*`; `total_bits` bounds the stream.
fn getBits(stream: []const u8, total_bits: usize, pos: *usize, n: u8) error{Corrupt}!u64 {
    if (pos.* + n > total_bits) return error.Corrupt;
    var acc: u64 = 0;
    var remaining: u8 = n;
    while (remaining > 0) {
        const idx = pos.* / 8;
        const avail: u8 = 8 - @as(u8, @intCast(pos.* % 8));
        const take: u8 = @min(avail, remaining);
        const mask: u8 = @truncate((@as(u16, 1) << @intCast(take)) - 1);
        const chunk: u8 = (stream[idx] >> @as(u3, @intCast(avail - take))) & mask;
        acc = (acc << @as(u6, @intCast(take))) | chunk;
        pos.* += take;
        remaining -= take;
    }
    return acc;
}

/// Field width of each timestamp bucket (index = bucket number).
const dod_field_bits = [5]u8{ 0, 7, 9, 12, 64 };
/// Prefix length ('0', '10', '110', '1110', '1111') of each bucket.
const dod_prefix_bits = [5]u8{ 1, 2, 3, 4, 4 };

fn dodBucket(dod: i64) u3 {
    if (dod == 0) return 0;
    if (dod >= -64 and dod <= 63) return 1;
    if (dod >= -256 and dod <= 255) return 2;
    if (dod >= -2048 and dod <= 2047) return 3;
    return 4;
}

const ValKind = enum { zero, reuse, window };

/// Everything `append` decides about one sample before touching the buffer,
/// including the exact bit cost (so a refused sample leaves no trace).
const Plan = struct {
    delta: i64,
    dod: i64,
    bucket: u3,
    x: u64,
    val: ValKind,
    lz: u8,
    tz: u8,
    sig: u8,
    bits: usize,
};

/// Encoder for one block. The whole block lives inside the struct: no
/// allocation, and the struct is cheap to copy (about 1 KiB).
pub const Writer = struct {
    buf: [max_block_bytes]u8 = [_]u8{0} ** max_block_bytes,
    /// Bits used in the stream (after the 2-byte header).
    nbits: usize = 0,
    n: u16 = 0,
    first_ts: i64 = 0,
    last_ts: i64 = 0,
    last_delta: i64 = 0,
    last_bits: u64 = 0,
    have_window: bool = false,
    win_lz: u8 = 0,
    win_sig: u8 = 0,

    /// An empty writer.
    pub fn init() Writer {
        return .{};
    }

    /// Number of samples appended so far.
    pub fn count(w: *const Writer) u16 {
        return w.n;
    }

    /// Timestamp of the first sample; valid when `count() >= 1`.
    pub fn firstTs(w: *const Writer) i64 {
        std.debug.assert(w.n >= 1);
        return w.first_ts;
    }

    /// Timestamp of the last sample; valid when `count() >= 1`.
    pub fn lastTs(w: *const Writer) i64 {
        std.debug.assert(w.n >= 1);
        return w.last_ts;
    }

    /// The encoded block (header plus padded stream); valid until the next
    /// `append`.
    pub fn bytes(w: *Writer) []const u8 {
        return w.buf[0 .. header_bytes + (w.nbits + 7) / 8];
    }

    /// Appends one sample. `error.OutOfOrder` when `s.ts` is not strictly
    /// greater than the last timestamp (checked first, so an invalid sample is
    /// reported even on a full block); `error.BlockFull` when the sample would
    /// push the encoded size over `max_block_bytes` or the count over
    /// `max_block_samples`. Both errors leave the writer unchanged.
    pub fn append(w: *Writer, s: Sample) error{ BlockFull, OutOfOrder }!void {
        if (w.n != 0 and s.ts <= w.last_ts) return error.OutOfOrder;
        if (w.n >= max_block_samples) return error.BlockFull;
        const p = w.plan(s);
        if (header_bytes + (w.nbits + p.bits + 7) / 8 > max_block_bytes) return error.BlockFull;
        w.commit(s, p);
    }

    fn plan(w: *const Writer, s: Sample) Plan {
        var p = Plan{ .delta = 0, .dod = 0, .bucket = 0, .x = 0, .val = .zero, .lz = 0, .tz = 0, .sig = 0, .bits = first_sample_bits };
        if (w.n == 0) return p;
        p.delta = @bitCast(@as(u64, @bitCast(s.ts)) -% @as(u64, @bitCast(w.last_ts)));
        p.dod = p.delta -% w.last_delta;
        p.bucket = dodBucket(p.dod);
        p.bits = dod_prefix_bits[p.bucket] + dod_field_bits[p.bucket];
        p.x = @as(u64, @bitCast(s.value)) ^ w.last_bits;
        if (p.x == 0) {
            p.bits += 1;
            return p;
        }
        p.lz = @min(@as(u8, @clz(p.x)), 31);
        p.tz = @ctz(p.x);
        p.sig = 64 - p.lz - p.tz;
        if (w.have_window and p.lz >= w.win_lz and p.tz >= 64 - w.win_lz - w.win_sig) {
            p.val = .reuse;
            p.bits += 2 + w.win_sig;
        } else {
            p.val = .window;
            p.bits += 2 + 5 + 6 + p.sig;
        }
        return p;
    }

    fn commit(w: *Writer, s: Sample, p: Plan) void {
        const stream = w.buf[header_bytes..];
        var pos = w.nbits;
        const bits_value: u64 = @bitCast(s.value);
        if (w.n == 0) {
            putBits(stream, &pos, @bitCast(s.ts), 64);
            putBits(stream, &pos, bits_value, 64);
            w.first_ts = s.ts;
        } else {
            // Timestamp record: prefix ones followed by a zero (none after the
            // last bucket), then the two's-complement field.
            const prefix_ones: u8 = if (p.bucket == 4) 4 else p.bucket;
            putBits(stream, &pos, (@as(u64, 1) << @as(u6, @intCast(prefix_ones))) - 1, prefix_ones);
            if (p.bucket != 4) putBits(stream, &pos, 0, 1);
            putBits(stream, &pos, @bitCast(p.dod), dod_field_bits[p.bucket]);
            switch (p.val) {
                .zero => putBits(stream, &pos, 0, 1),
                .reuse => {
                    putBits(stream, &pos, 0b10, 2);
                    putBits(stream, &pos, p.x >> @as(u6, @intCast(64 - w.win_lz - w.win_sig)), w.win_sig);
                },
                .window => {
                    putBits(stream, &pos, 0b11, 2);
                    putBits(stream, &pos, p.lz, 5);
                    putBits(stream, &pos, p.sig - 1, 6);
                    putBits(stream, &pos, p.x >> @as(u6, @intCast(p.tz)), p.sig);
                    w.have_window = true;
                    w.win_lz = p.lz;
                    w.win_sig = p.sig;
                },
            }
        }
        std.debug.assert(pos == w.nbits + p.bits);
        w.nbits = pos;
        w.n += 1;
        w.last_ts = s.ts;
        w.last_delta = p.delta;
        w.last_bits = bits_value;
        std.mem.writeInt(u16, w.buf[0..2], w.n, .big);
    }
};

/// Lazy decoder over a borrowed block.
pub const Reader = struct {
    stream: []const u8,
    total: u16,
    idx: u16 = 0,
    pos: usize = 0,
    prev_ts: i64 = 0,
    prev_delta: i64 = 0,
    prev_bits: u64 = 0,
    have_window: bool = false,
    win_lz: u8 = 0,
    win_sig: u8 = 0,

    /// Validates the header (at least 2 bytes, count >= 1). The stream itself
    /// is validated while decoding.
    pub fn init(block: []const u8) error{Corrupt}!Reader {
        if (block.len < header_bytes) return error.Corrupt;
        const total = std.mem.readInt(u16, block[0..2], .big);
        // A writer never produces more; a reader trusting a larger count would
        // let a corrupt header size a consumer's buffer.
        if (total == 0 or total > max_block_samples) return error.Corrupt;
        return .{ .stream = block[header_bytes..], .total = total };
    }

    /// Points the reader at a different copy of the block it was created
    /// from, keeping the decode position. For callers that hold the block in a
    /// buffer inside a struct which may be moved between `next` calls. The
    /// bytes at `block` must be identical to the original block (same length
    /// and content); this is not checked beyond a length assertion.
    pub fn rebind(r: *Reader, block: []const u8) void {
        std.debug.assert(block.len == header_bytes + r.stream.len);
        r.stream = block[header_bytes..];
    }

    /// Number of samples the header announces.
    pub fn count(r: *const Reader) u16 {
        return r.total;
    }

    /// Next sample, `null` after `count()` samples. `error.Corrupt` on a
    /// truncated stream, a timestamp that is not strictly ascending, a window
    /// record with `sig > 64` or `lz + sig > 64`, a window reuse before any
    /// window, or nonzero padding / trailing bytes after the last sample (the
    /// last sample's `next` reports those).
    pub fn next(r: *Reader) error{Corrupt}!?Sample {
        if (r.idx >= r.total) return null;
        const total_bits = r.stream.len * 8;
        var s: Sample = undefined;
        if (r.idx == 0) {
            const ts = try getBits(r.stream, total_bits, &r.pos, 64);
            r.prev_bits = try getBits(r.stream, total_bits, &r.pos, 64);
            r.prev_ts = @bitCast(ts);
        } else {
            var bucket: u3 = 0;
            while (bucket < 4) : (bucket += 1) {
                if (try getBits(r.stream, total_bits, &r.pos, 1) == 0) break;
            }
            const width = dod_field_bits[bucket];
            const raw = try getBits(r.stream, total_bits, &r.pos, width);
            const dod: i64 = switch (width) {
                0 => 0,
                64 => @bitCast(raw),
                else => @as(i64, @bitCast(raw << @as(u6, @intCast(64 - width)))) >> @as(u6, @intCast(64 - width)),
            };
            const delta = r.prev_delta +% dod;
            const ts: i64 = @bitCast(@as(u64, @bitCast(r.prev_ts)) +% @as(u64, @bitCast(delta)));
            if (ts <= r.prev_ts) return error.Corrupt;
            r.prev_delta = delta;
            r.prev_ts = ts;
            if (try getBits(r.stream, total_bits, &r.pos, 1) == 1) {
                if (try getBits(r.stream, total_bits, &r.pos, 1) == 1) {
                    const lz: u8 = @intCast(try getBits(r.stream, total_bits, &r.pos, 5));
                    const sig: u8 = @as(u8, @intCast(try getBits(r.stream, total_bits, &r.pos, 6))) + 1;
                    if (sig > 64 or @as(u16, lz) + sig > 64) return error.Corrupt;
                    r.have_window = true;
                    r.win_lz = lz;
                    r.win_sig = sig;
                } else if (!r.have_window) {
                    return error.Corrupt;
                }
                const field = try getBits(r.stream, total_bits, &r.pos, r.win_sig);
                r.prev_bits ^= field << @as(u6, @intCast(64 - r.win_lz - r.win_sig));
            }
        }
        s = .{ .ts = r.prev_ts, .value = @bitCast(r.prev_bits) };
        r.idx += 1;
        if (r.idx == r.total) {
            // The stream must end exactly here, with zero padding.
            if ((r.pos + 7) / 8 != r.stream.len) return error.Corrupt;
            const used = r.pos % 8;
            if (used != 0 and r.stream[r.stream.len - 1] & ((@as(u8, 1) << @as(u3, @intCast(8 - used))) - 1) != 0)
                return error.Corrupt;
        }
        return s;
    }
};

/// Timestamp of the first sample, read from the header without a full decode.
pub fn firstTs(block: []const u8) error{Corrupt}!i64 {
    if (block.len < header_bytes + 8) return error.Corrupt;
    if (std.mem.readInt(u16, block[0..2], .big) == 0) return error.Corrupt;
    return @bitCast(std.mem.readInt(u64, block[header_bytes..][0..8], .big));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn bitsOf(f: f64) u64 {
    return @bitCast(f);
}

fn fromBits(b: u64) f64 {
    return @bitCast(b);
}

/// Decodes `block` fully and compares bit-exactly with `want`.
fn expectDecodes(block: []const u8, want: []const Sample) !void {
    var r = try Reader.init(block);
    try testing.expectEqual(@as(u16, @intCast(want.len)), r.count());
    for (want) |w| {
        const got = (try r.next()) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(w.ts, got.ts);
        try testing.expectEqual(bitsOf(w.value), bitsOf(got.value));
    }
    try testing.expect((try r.next()) == null);
    try testing.expectEqual(w_firstTs(want), try firstTs(block));
}

fn w_firstTs(want: []const Sample) i64 {
    return want[0].ts;
}

/// Appends samples until the block is full; decodes and compares the encoded
/// prefix. Returns how many samples fit.
fn roundTripPrefix(samples: []const Sample) !usize {
    var w = Writer.init();
    var n: usize = 0;
    for (samples) |s| {
        w.append(s) catch |e| switch (e) {
            error.BlockFull => break,
            error.OutOfOrder => return error.TestUnexpectedResult,
        };
        n += 1;
    }
    try testing.expect(w.bytes().len <= max_block_bytes);
    try expectDecodes(w.bytes(), samples[0..n]);
    return n;
}

fn roundTrip(samples: []const Sample) !void {
    try testing.expectEqual(samples.len, try roundTripPrefix(samples));
}

test "Reader.init refuses a header count above max_block_samples" {
    var buf = [_]u8{ 0, 0, 0, 0 };
    std.mem.writeInt(u16, buf[0..2], max_block_samples + 1, .big);
    try std.testing.expectError(error.Corrupt, Reader.init(&buf));
}

test "single sample round trip and size" {
    // Kills: layout drift of sample 0 (raw ts + raw value).
    const s = [_]Sample{.{ .ts = -123456789, .value = -2.5 }};
    try roundTrip(&s);
    var w = Writer.init();
    try w.append(s[0]);
    try testing.expectEqual(@as(usize, 2 + 16), w.bytes().len);
    try testing.expectEqual(@as(u16, 1), w.count());
    try testing.expectEqual(@as(i64, -123456789), w.firstTs());
    try testing.expectEqual(@as(i64, -123456789), w.lastTs());
}

test "constant series costs exactly one bit per field" {
    // Kills (b): prev_delta not updated (dod would stay nonzero) and a
    // wrong zero-record width. Layout: 128 bits + sample 1 (dod 1 = 9 bits,
    // value 1 bit) + 2 bits per further sample.
    var w = Writer.init();
    var buf: [100]Sample = undefined;
    for (&buf, 0..) |*s, i| {
        s.* = .{ .ts = @intCast(i + 1), .value = 42.5 };
        try w.append(s.*);
    }
    try testing.expectEqual(@as(usize, 128 + 10 + 98 * 2), w.nbits);
    try expectDecodes(w.bytes(), &buf);
}

test "regular steps: prev_delta is carried (dod 0 after the first delta)" {
    // Kills (b): with a stale prev_delta each record would be dod = step
    // (a 9..16 bit bucket) instead of the 1-bit zero record.
    for ([_]i64{ 1, 15, 1000, 1_000_000_000 }) |step| {
        var buf: [60]Sample = undefined;
        var w = Writer.init();
        for (&buf, 0..) |*s, i| {
            s.* = .{ .ts = 1_700_000_000_000 + @as(i64, @intCast(i)) * step, .value = 7.0 };
            try w.append(s.*);
        }
        // sample 1 pays for the first delta, all later ones 2 bits.
        const first_dod_bits: usize = switch (step) {
            1, 15 => 9,
            1000 => 16,
            else => 68,
        };
        try testing.expectEqual(@as(usize, 128 + first_dod_bits + 1 + 58 * 2), w.nbits);
        try expectDecodes(w.bytes(), &buf);
    }
}

/// Builds ts0=0, ts1=base, ts2 with `dod` relative to base, ts3 with `-dod`
/// relative to that, so the delta returns to base.
fn dodSamples(base: i64, dod: i64) [4]Sample {
    const d2 = base + dod;
    const d3 = d2 - dod;
    return .{
        .{ .ts = 0, .value = 1.0 },
        .{ .ts = base, .value = 1.0 },
        .{ .ts = base + d2, .value = 1.0 },
        .{ .ts = base + d2 + d3, .value = 1.0 },
    };
}

test "dod bucket boundaries cost the exact number of bits" {
    // Kills (a): any off-by-one in a bucket range changes the record size of
    // one of the boundary values below. (value record is a constant 1 bit.)
    const cases = [_]struct { dod: i64, ts_bits: usize }{
        .{ .dod = 0, .ts_bits = 1 },
        .{ .dod = 1, .ts_bits = 9 },
        .{ .dod = -1, .ts_bits = 9 },
        .{ .dod = 63, .ts_bits = 9 },
        .{ .dod = -64, .ts_bits = 9 },
        .{ .dod = 64, .ts_bits = 12 },
        .{ .dod = -65, .ts_bits = 12 },
        .{ .dod = 255, .ts_bits = 12 },
        .{ .dod = -256, .ts_bits = 12 },
        .{ .dod = 256, .ts_bits = 16 },
        .{ .dod = -257, .ts_bits = 16 },
        .{ .dod = 2047, .ts_bits = 16 },
        .{ .dod = -2048, .ts_bits = 16 },
        .{ .dod = 2048, .ts_bits = 68 },
        .{ .dod = -2049, .ts_bits = 68 },
        .{ .dod = 1 << 40, .ts_bits = 68 },
        .{ .dod = -(1 << 40), .ts_bits = 68 },
    };
    const base: i64 = 1 << 50;
    for (cases) |c| {
        const ss = dodSamples(base, c.dod);
        var w = Writer.init();
        try w.append(ss[0]);
        try w.append(ss[1]);
        const before = w.nbits;
        try w.append(ss[2]);
        try testing.expectEqual(c.ts_bits + 1, w.nbits - before);
        const mid = w.nbits;
        try w.append(ss[3]);
        // The return step has dod = -c.dod, mirrored bucket sizes except at
        // the asymmetric ends of the two's-complement range.
        const back = dodBucket(-c.dod);
        try testing.expectEqual(@as(usize, dod_prefix_bits[back]) + dod_field_bits[back] + 1, w.nbits - mid);
        try expectDecodes(w.bytes(), &ss);
    }
    // All dods in one block, back to back.
    var all: [2 + 2 * cases.len]Sample = undefined;
    all[0] = .{ .ts = 0, .value = 0 };
    all[1] = .{ .ts = base, .value = 0 };
    var delta = base;
    var ts = base;
    for (cases, 0..) |c, i| {
        delta += c.dod;
        ts += delta;
        all[2 + 2 * i] = .{ .ts = ts, .value = 0 };
        delta -= c.dod;
        ts += delta;
        all[3 + 2 * i] = .{ .ts = ts, .value = 0 };
    }
    try roundTrip(&all);
}

test "extreme timestamps round trip (wrapping dod)" {
    // Kills (a)/(b) at the wrap-around edge: raw 64-bit bucket, dod that
    // overflows i64 and a block spanning minInt..maxInt.
    const lo = std.math.minInt(i64);
    const hi = std.math.maxInt(i64);
    try roundTrip(&.{ .{ .ts = lo, .value = 0 }, .{ .ts = hi, .value = 1 } });
    try roundTrip(&.{ .{ .ts = lo, .value = 0 }, .{ .ts = 0, .value = 1 }, .{ .ts = hi, .value = 2 } });
    try roundTrip(&.{ .{ .ts = lo, .value = 0 }, .{ .ts = lo + 1, .value = 1 }, .{ .ts = 2, .value = 2 } }); // dod == minInt
    try roundTrip(&.{ .{ .ts = lo, .value = 0 }, .{ .ts = -1, .value = 1 }, .{ .ts = 0, .value = 2 }, .{ .ts = hi, .value = 3 } });
    try roundTrip(&.{ .{ .ts = hi - 2, .value = 0 }, .{ .ts = hi - 1, .value = 1 }, .{ .ts = hi, .value = 2 } });
    try roundTrip(&.{ .{ .ts = lo, .value = 0 }, .{ .ts = lo + 1, .value = 0 }, .{ .ts = lo + 2, .value = 0 } });
    // Random full-range sorted unique timestamps.
    var prng = std.Random.DefaultPrng.init(0xA11CE);
    const rnd = prng.random();
    for (0..200) |_| {
        var raw: [40]i64 = undefined;
        for (&raw) |*t| t.* = @bitCast(rnd.int(u64));
        std.mem.sort(i64, &raw, {}, std.sort.asc(i64));
        var ss: [40]Sample = undefined;
        var n: usize = 0;
        for (raw) |t| {
            if (n > 0 and ss[n - 1].ts == t) continue;
            ss[n] = .{ .ts = t, .value = fromBits(rnd.int(u64)) };
            n += 1;
        }
        _ = try roundTripPrefix(ss[0..n]);
    }
}

/// Appends `vals` as values at ts 0, 1, 2, ... and returns the bit cost of the
/// record of each sample i >= 2 (minus the 1-bit zero timestamp record).
fn valueCosts(vals: []const u64, out: []usize) !void {
    var w = Writer.init();
    for (vals, 0..) |v, i| {
        const before = w.nbits;
        try w.append(.{ .ts = @intCast(i), .value = fromBits(v) });
        if (i >= 2) out[i] = w.nbits - before - 1;
    }
    var back: [16]Sample = undefined;
    for (vals, 0..) |v, i| back[i] = .{ .ts = @intCast(i), .value = fromBits(v) };
    try expectDecodes(w.bytes(), back[0..vals.len]);
}

test "value windows: reuse vs new window, exact bit costs" {
    // Window A: lz = 10, sig = 20, tz = 34 (v0 = 0, v1 = A, so sample 1 opens it).
    const a: u64 = ((@as(u64, 1) << 20) - 1) << 34;
    var c: [16]usize = undefined;
    const reuse_cost: usize = 1 + 1 + 20;
    const new_one_bit: usize = 1 + 1 + 5 + 6 + 1;

    // Same window exactly (boundary on both sides) -> reuse.
    try valueCosts(&.{ 0, a, 0 }, &c);
    try testing.expectEqual(reuse_cost, c[2]);
    // Strictly inside the window on both sides (lz 29 > 10, tz 34 == 34 edge
    // is covered above; here the top is looser) -> reuse.
    try valueCosts(&.{ 0, a, a ^ (@as(u64, 1) << 34) }, &c);
    try testing.expectEqual(reuse_cost, c[2]);
    // Single bit at the very top of the window (lz == prev_lz) -> reuse.
    try valueCosts(&.{ 0, a, a ^ (@as(u64, 1) << 53) }, &c);
    try testing.expectEqual(reuse_cost, c[2]);
    // Kills (c) tightened to equality: lz 29 > prev_lz, tz 34 -> reuse.
    try valueCosts(&.{ 0, a, a ^ (@as(u64, 1) << 40) }, &c);
    try testing.expectEqual(reuse_cost, c[2]);
    // Kills (c) loosened lz: one bit above the window (lz 9 < 10) -> new window.
    try valueCosts(&.{ 0, a, a ^ (@as(u64, 1) << 54) }, &c);
    try testing.expectEqual(new_one_bit, c[2]);
    // Kills (c) loosened tz: one bit below the window (tz 33 < 34) -> new window.
    try valueCosts(&.{ 0, a, a ^ (@as(u64, 1) << 33) }, &c);
    try testing.expectEqual(new_one_bit, c[2]);
    // The window is replaced by a new-window record (lz 9, sig 1, tz 54), so
    // the old window A no longer applies: bit 34 now needs another new window.
    try valueCosts(&.{ 0, a, a ^ (@as(u64, 1) << 54), (a ^ (@as(u64, 1) << 54)) ^ (@as(u64, 1) << 34) }, &c);
    try testing.expectEqual(new_one_bit, c[2]);
    try testing.expectEqual(new_one_bit, c[3]);
    // A reuse record does NOT change the window: after reuse of A, bit 34
    // (inside A) still reuses.
    try valueCosts(&.{ 0, a, 0, a }, &c);
    try testing.expectEqual(reuse_cost, c[2]);
    try testing.expectEqual(reuse_cost, c[3]);
    // No window yet: a first nonzero xor at sample 1 opens one; a repeated
    // value afterwards is '0'.
    try valueCosts(&.{ 5, 5, 5 }, &c);
    try testing.expectEqual(@as(usize, 1), c[2]);
}

test "alternating two values takes the reuse path after the first window" {
    // Kills (c): both paths taken, asserted by size. x = lo ^ hi is constant,
    // so after the opening window every record is 1 + 1 + sig bits.
    const lo = bitsOf(21.5);
    const hi = bitsOf(21.75);
    const x = lo ^ hi;
    const sig: usize = 64 - @clz(x) - @ctz(x);
    var w = Writer.init();
    var buf: [40]Sample = undefined;
    for (&buf, 0..) |*s, i| {
        s.* = .{ .ts = @intCast(i * 10), .value = if (i % 2 == 0) 21.5 else 21.75 };
        try w.append(s.*);
    }
    // sample 1: dod 10 (9 bits) + new window; samples 2..: dod 0 (1 bit) + reuse.
    const expect = 128 + 9 + (2 + 5 + 6 + sig) + 38 * (1 + 2 + sig);
    try testing.expectEqual(expect, w.nbits);
    try expectDecodes(w.bytes(), &buf);
}

test "leading zeros are clamped to 31" {
    // Kills (d): x = 1 has 63 leading zeros, which does not fit the 5-bit lz
    // field; clamped to 31 the window is sig = 33 bits.
    var c: [16]usize = undefined;
    try valueCosts(&.{ 0, 1, 0, 1, 3 }, &c);
    try testing.expectEqual(@as(usize, 1 + 1 + 33), c[2]); // reuse of (31, 33)
    try testing.expectEqual(@as(usize, 1 + 1 + 33), c[3]);
    try testing.expectEqual(@as(usize, 1 + 1 + 33), c[4]);
    // Exactly at the clamp edge, and one below / above it.
    var w = Writer.init();
    try w.append(.{ .ts = 0, .value = 0 });
    const n0 = w.nbits;
    try w.append(.{ .ts = 1, .value = fromBits(1) }); // lz 63 -> 31, tz 0, sig 33
    try testing.expectEqual(@as(usize, 9 + 2 + 5 + 6 + 33), w.nbits - n0);
    for ([_]u6{ 0, 1, 31, 32, 33, 40, 62, 63 }) |sh| {
        const x = @as(u64, 1) << sh;
        const lz: u8 = @min(@as(u8, @clz(x)), 31);
        const sig: usize = 64 - lz - sh;
        var w2 = Writer.init();
        try w2.append(.{ .ts = 0, .value = 0 });
        const before = w2.nbits;
        try w2.append(.{ .ts = 1, .value = fromBits(x) });
        try testing.expectEqual(9 + 2 + 5 + 6 + sig, w2.nbits - before);
        try expectDecodes(w2.bytes(), &.{ .{ .ts = 0, .value = 0 }, .{ .ts = 1, .value = fromBits(x) } });
    }
}

test "special values round trip bit-exactly" {
    const specials = [_]u64{
        0,
        0x8000000000000000, // -0.0
        bitsOf(1.0),
        bitsOf(-1.0),
        0x7FF0000000000000, // +Inf
        0xFFF0000000000000, // -Inf
        0x7FF8000000000000, // quiet NaN
        0x7FF8000000000001, // NaN payload 1
        0xFFF8DEADBEEF1234, // negative NaN with payload
        0x7FF0000000000001, // signalling NaN
        bitsOf(std.math.floatMax(f64)),
        bitsOf(std.math.floatTrueMin(f64)),
        0xFFFFFFFFFFFFFFFF,
        0x0000000000000001,
    };
    var buf: [specials.len * 3]Sample = undefined;
    var n: usize = 0;
    for (specials) |a| {
        for (specials[0..3]) |b| {
            buf[n] = .{ .ts = @intCast(n * 3), .value = fromBits(a) };
            n += 1;
            _ = b;
        }
    }
    try roundTrip(buf[0..n]);
    // Every ordered pair (xor of any two patterns).
    var pairs: [specials.len * specials.len]Sample = undefined;
    var k: usize = 0;
    for (specials) |a| for (specials) |b| {
        pairs[k] = .{ .ts = @intCast(k), .value = fromBits(if (k % 2 == 0) a else b) };
        k += 1;
    };
    _ = try roundTripPrefix(pairs[0..k]);
    // Integers as floats and a slowly varying gauge.
    var ints: [200]Sample = undefined;
    for (&ints, 0..) |*s, i| s.* = .{ .ts = @intCast(i * 15), .value = @floatFromInt(i * 3) };
    _ = try roundTripPrefix(&ints);
    var g: [200]Sample = undefined;
    for (&g, 0..) |*s, i| s.* = .{ .ts = @intCast(i * 15), .value = 20.0 + @as(f64, @floatFromInt(i % 7)) * 0.25 };
    _ = try roundTripPrefix(&g);
}

const TsMode = enum { regular, jitter, random_delta, full_range };
const ValMode = enum { random_bits, constant, gauge, integers, alternating, specials, sparse_xor };

fn genBlock(rnd: std.Random, out: []Sample) usize {
    const want = rnd.intRangeAtMost(usize, 1, out.len);
    const tm = rnd.enumValue(TsMode);
    const vm = rnd.enumValue(ValMode);
    const steps = [_]i64{ 1, 15, 1000, 60_000 };
    const step = if (rnd.boolean()) steps[rnd.uintLessThan(usize, steps.len)] else rnd.intRangeAtMost(i64, 1, 1_000_000_000);
    const jit_choices = [_]i64{ 1, 5, 60, 300, 3000 };
    const jit = jit_choices[rnd.uintLessThan(usize, jit_choices.len)];
    const kmax = rnd.intRangeAtMost(u6, 1, 62);

    // Timestamps.
    var n: usize = 0;
    if (tm == .full_range) {
        var raw: [1100]i64 = undefined;
        for (raw[0..want]) |*t| t.* = @bitCast(rnd.int(u64));
        std.mem.sort(i64, raw[0..want], {}, std.sort.asc(i64));
        for (raw[0..want]) |t| {
            if (n > 0 and out[n - 1].ts == t) continue;
            out[n].ts = t;
            n += 1;
        }
    } else {
        var ts: i64 = rnd.intRangeAtMost(i64, -1_000_000, 1_700_000_000_000);
        while (n < want) : (n += 1) {
            out[n].ts = ts;
            const delta: i64 = switch (tm) {
                .regular => step,
                .jitter => @max(1, step + rnd.intRangeAtMost(i64, -jit, jit)),
                .random_delta => @as(i64, 1) + @as(i64, @intCast(rnd.uintLessThan(u64, @as(u64, 1) << kmax))),
                .full_range => unreachable,
            };
            const sum = @addWithOverflow(ts, delta);
            if (sum[1] != 0) {
                n += 1;
                break;
            }
            ts = sum[0];
        }
    }

    // Values.
    var prev: u64 = rnd.int(u64);
    var gauge: i64 = rnd.intRangeAtMost(i64, -100, 100);
    const lo = rnd.int(u64);
    const hi = rnd.int(u64);
    const special = [_]u64{ 0, 0x8000000000000000, 0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000001, 0xFFF8DEADBEEF1234, 1 };
    for (out[0..n], 0..) |*s, i| {
        const b: u64 = switch (vm) {
            .random_bits => rnd.int(u64),
            .constant => prev,
            .gauge => blk: {
                if (rnd.uintLessThan(u8, 4) == 0) gauge += if (rnd.boolean()) 1 else -1;
                break :blk bitsOf(@as(f64, @floatFromInt(gauge)) * 0.25);
            },
            .integers => bitsOf(@floatFromInt(rnd.intRangeAtMost(i32, -1000, 1000))),
            .alternating => if (i % 2 == 0) lo else hi,
            .specials => if (rnd.boolean()) special[rnd.uintLessThan(usize, special.len)] else rnd.int(u64),
            .sparse_xor => prev ^ (rnd.int(u64) >> rnd.int(u6) << rnd.int(u6)),
        };
        s.value = fromBits(b);
        prev = b;
    }
    return n;
}

test "20000 random blocks decode to exactly what was encoded" {
    // Kills (a)-(d) statistically: every strategy mix, bucket and window path.
    var prng = std.Random.DefaultPrng.init(0x601_1A);
    const rnd = prng.random();
    var buf: [1100]Sample = undefined;
    var total_encoded: usize = 0;
    for (0..20_000) |_| {
        const n = genBlock(rnd, &buf);
        total_encoded += try roundTripPrefix(buf[0..n]);
    }
    try testing.expect(total_encoded > 20_000);
}

test "BlockFull at the byte cap leaves the writer unchanged" {
    // Fill with random-bit values at a regular step until refused, then with
    // 2-bit records (same value, same step) until the last bit is used.
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    var w = Writer.init();
    var ts: i64 = 1000;
    var last = Sample{ .ts = 0, .value = 0 };
    while (true) : (ts += 7) {
        const s = Sample{ .ts = ts, .value = fromBits(rnd.int(u64)) };
        w.append(s) catch |e| {
            try testing.expectEqual(error.BlockFull, e);
            break;
        };
        last = s;
    }
    try testing.expect(w.bytes().len <= max_block_bytes);
    const snap = w;
    const snap_bytes = snap.buf;
    // The refused sample really would not fit, and a retry stays refused.
    const refused = Sample{ .ts = ts, .value = fromBits(rnd.int(u64)) };
    const p = w.plan(refused);
    try testing.expect(header_bytes + (w.nbits + p.bits + 7) / 8 > max_block_bytes);
    try testing.expectError(error.BlockFull, w.append(refused));
    try testing.expectEqualSlices(u8, &snap_bytes, &w.buf);
    try testing.expectEqual(snap.nbits, w.nbits);
    try testing.expectEqual(snap.n, w.n);
    try testing.expectEqual(snap.last_ts, w.last_ts);
    try testing.expectEqual(snap.last_delta, w.last_delta);
    try testing.expectEqual(snap.last_bits, w.last_bits);
    try testing.expectEqual(snap.win_lz, w.win_lz);
    try testing.expectEqual(snap.win_sig, w.win_sig);
    // Cheap records (equal value, dod 0) still fit until fewer than 2 bits
    // remain, i.e. the block ends at exactly max_block_bytes.
    var cheap_ts = last.ts + 7;
    while (true) : (cheap_ts += 7) {
        w.append(.{ .ts = cheap_ts, .value = last.value }) catch break;
    }
    // The refusal above came from the byte cap, not the count cap.
    try testing.expect(w.count() < max_block_samples);
    try testing.expectEqual(max_block_bytes, w.bytes().len);
    const before_bytes = w.buf;
    try testing.expectError(error.BlockFull, w.append(.{ .ts = cheap_ts, .value = last.value }));
    try testing.expectEqualSlices(u8, &before_bytes, &w.buf);
    // The full block decodes.
    var r = try Reader.init(w.bytes());
    var got: usize = 0;
    while (try r.next()) |_| got += 1;
    try testing.expectEqual(@as(usize, w.count()), got);
}

test "BlockFull at max_block_samples" {
    var w = Writer.init();
    for (0..max_block_samples) |i| try w.append(.{ .ts = @intCast(i), .value = 1.5 });
    try testing.expectEqual(max_block_samples, w.count());
    const before = w.buf;
    try testing.expectError(error.BlockFull, w.append(.{ .ts = 5000, .value = 1.5 }));
    try testing.expectEqual(max_block_samples, w.count());
    try testing.expectEqualSlices(u8, &before, &w.buf);
    var r = try Reader.init(w.bytes());
    var got: usize = 0;
    while (try r.next()) |_| got += 1;
    try testing.expectEqual(@as(usize, max_block_samples), got);
}

test "OutOfOrder on equal and smaller timestamps" {
    var w = Writer.init();
    // Any first timestamp is fine, including minInt.
    try w.append(.{ .ts = std.math.minInt(i64), .value = 1 });
    try w.append(.{ .ts = -5, .value = 2 });
    const before = w;
    try testing.expectError(error.OutOfOrder, w.append(.{ .ts = -5, .value = 3 }));
    try testing.expectError(error.OutOfOrder, w.append(.{ .ts = -6, .value = 3 }));
    try testing.expectError(error.OutOfOrder, w.append(.{ .ts = std.math.minInt(i64), .value = 3 }));
    try testing.expectEqualSlices(u8, &before.buf, &w.buf);
    try testing.expectEqual(before.nbits, w.nbits);
    try testing.expectEqual(@as(u16, 2), w.count());
    try w.append(.{ .ts = -4, .value = 3 });
    try testing.expectEqual(@as(i64, -4), w.lastTs());
    try testing.expectEqual(std.math.minInt(i64), w.firstTs());
}

fn drain(block: []const u8) error{Corrupt}!void {
    var r = try Reader.init(block);
    while (try r.next()) |_| {}
}

/// Hand-assembles a block (count header + bit stream) for malformed-input tests.
const Craft = struct {
    buf: [64]u8 = [_]u8{0} ** 64,
    pos: usize = 0,
    n: u16,

    fn put(c: *Craft, v: u64, bits: u8) void {
        putBits(c.buf[2..], &c.pos, v, bits);
    }

    fn block(c: *Craft) []const u8 {
        std.mem.writeInt(u16, c.buf[0..2], c.n, .big);
        return c.buf[0 .. 2 + (c.pos + 7) / 8];
    }
};

test "Reader rejects malformed blocks" {
    try testing.expectError(error.Corrupt, Reader.init(&.{}));
    try testing.expectError(error.Corrupt, Reader.init(&.{0x00}));
    try testing.expectError(error.Corrupt, Reader.init(&.{ 0x00, 0x00 }));
    try testing.expectError(error.Corrupt, Reader.init(&.{ 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }));
    try testing.expectError(error.Corrupt, firstTs(&.{ 0x00, 0x01, 1, 2, 3 }));
    try testing.expectError(error.Corrupt, firstTs(&.{}));
    // Header only, count 1: stream truncated.
    var only_header = try Reader.init(&.{ 0x00, 0x01 });
    try testing.expectError(error.Corrupt, only_header.next());

    // Every proper prefix of a valid block is rejected.
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    var buf: [200]Sample = undefined;
    for (&buf, 0..) |*s, i| s.* = .{ .ts = @intCast(i * 15 + rnd.uintLessThan(u8, 3)), .value = fromBits(rnd.int(u64) >> rnd.int(u6)) };
    var w = Writer.init();
    var cnt: usize = 0;
    for (buf) |s| {
        w.append(s) catch break;
        cnt += 1;
    }
    const full = w.bytes();
    try drain(full);
    for (0..full.len) |len| {
        try testing.expectError(error.Corrupt, drain(full[0..len]));
    }

    // Trailing garbage byte.
    var longer: [max_block_bytes + 1]u8 = undefined;
    @memcpy(longer[0..full.len], full);
    longer[full.len] = 0;
    try testing.expectError(error.Corrupt, drain(longer[0 .. full.len + 1]));
    longer[full.len] = 0xAB;
    try testing.expectError(error.Corrupt, drain(longer[0 .. full.len + 1]));

    // Count too large (stream ends early) and too small (bytes left over).
    var bad: [max_block_bytes]u8 = undefined;
    @memcpy(bad[0..full.len], full);
    std.mem.writeInt(u16, bad[0..2], @intCast(cnt + 1), .big);
    try testing.expectError(error.Corrupt, drain(bad[0..full.len]));
    std.mem.writeInt(u16, bad[0..2], @intCast(cnt - 1), .big);
    try testing.expectError(error.Corrupt, drain(bad[0..full.len]));

    // Nonzero padding: find a block whose stream does not end on a byte edge.
    var pw = Writer.init();
    var t: i64 = 0;
    while (pw.nbits % 8 == 0) : (t += 1) try pw.append(.{ .ts = t * 3, .value = fromBits(rnd.int(u64) >> 40) });
    var padded: [max_block_bytes]u8 = undefined;
    const pb = pw.bytes();
    @memcpy(padded[0..pb.len], pb);
    try drain(padded[0..pb.len]);
    const free_bits: u3 = @intCast(8 - pw.nbits % 8);
    padded[pb.len - 1] |= @as(u8, 1) << (free_bits - 1);
    try testing.expectError(error.Corrupt, drain(padded[0..pb.len]));

    // Timestamp not strictly ascending: delta 0 (dod 0), and a negative delta.
    var c1 = Craft{ .n = 2 };
    c1.put(100, 64);
    c1.put(0, 64);
    c1.put(0, 1); // dod 0 -> delta 0 -> equal ts
    c1.put(0, 1);
    try testing.expectError(error.Corrupt, drain(c1.block()));
    var c2 = Craft{ .n = 2 };
    c2.put(100, 64);
    c2.put(0, 64);
    c2.put(0b1111, 4);
    c2.put(@bitCast(@as(i64, -5)), 64);
    c2.put(0, 1);
    try testing.expectError(error.Corrupt, drain(c2.block()));
    // Same shape with a positive delta decodes (control).
    var c3 = Craft{ .n = 2 };
    c3.put(100, 64);
    c3.put(0, 64);
    c3.put(0b10, 2);
    c3.put(5, 7);
    c3.put(0, 1);
    try drain(c3.block());

    // Window record with lz + sig > 64 (lz 31, sig 40), then enough bits.
    var c4 = Craft{ .n = 2 };
    c4.put(100, 64);
    c4.put(0, 64);
    c4.put(0b10, 2);
    c4.put(5, 7);
    c4.put(0b11, 2);
    c4.put(31, 5);
    c4.put(39, 6);
    c4.put(0, 40);
    try testing.expectError(error.Corrupt, drain(c4.block()));
    // The same record with lz 24 (24 + 40 == 64) is valid (control).
    var c5 = Craft{ .n = 2 };
    c5.put(100, 64);
    c5.put(0, 64);
    c5.put(0b10, 2);
    c5.put(5, 7);
    c5.put(0b11, 2);
    c5.put(24, 5);
    c5.put(39, 6);
    c5.put(0, 40);
    try drain(c5.block());
    // Window reuse before any window was defined.
    var c6 = Craft{ .n = 2 };
    c6.put(100, 64);
    c6.put(0, 64);
    c6.put(0b10, 2);
    c6.put(5, 7);
    c6.put(0b10, 2);
    c6.put(0, 8);
    try testing.expectError(error.Corrupt, drain(c6.block()));
}

test "firstTs peeks without decoding" {
    var w = Writer.init();
    try w.append(.{ .ts = -42, .value = 1 });
    try w.append(.{ .ts = 7, .value = 2 });
    try testing.expectEqual(@as(i64, -42), try firstTs(w.bytes()));
    try testing.expectEqual(@as(i64, -42), try firstTs(w.bytes()[0..10]));
    try testing.expectError(error.Corrupt, firstTs(w.bytes()[0..9]));
}

test "size sanity: slowly varying gauge at a fixed 15 s step" {
    // Samples are packed greedily into as many blocks as the cap requires.
    var prng = std.Random.DefaultPrng.init(99);
    const rnd = prng.random();
    var all: [1000]Sample = undefined;
    var gauge: i64 = 80; // 20.0 in quarter steps, exactly representable
    for (&all, 0..) |*s, i| {
        if (rnd.uintLessThan(u8, 4) == 0) gauge += if (rnd.boolean()) 1 else -1;
        s.* = .{ .ts = 1_700_000_000 + @as(i64, @intCast(i)) * 15, .value = @as(f64, @floatFromInt(gauge)) * 0.25 };
    }
    var total: usize = 0;
    var blocks: usize = 0;
    var i: usize = 0;
    while (i < all.len) {
        const n = try roundTripPrefix(all[i..]);
        try testing.expect(n > 0);
        var w = Writer.init();
        for (all[i .. i + n]) |s| try w.append(s);
        total += w.bytes().len;
        blocks += 1;
        i += n;
    }
    // Measured: 1000 samples -> 458 bytes in 1 block (0.458 bytes/sample).
    const limit: usize = 2 * all.len; // <= 2 bytes/sample on average
    try testing.expect(total <= limit);
    try testing.expect(blocks >= 1);
}

test "rebind keeps the decode position on a moved copy" {
    var w = Writer.init();
    for (0..30) |i| try w.append(.{ .ts = @intCast(i * 10), .value = @floatFromInt(i * i) });
    var copy_a: [max_block_bytes]u8 = undefined;
    var copy_b: [max_block_bytes]u8 = undefined;
    const src = w.bytes();
    @memcpy(copy_a[0..src.len], src);
    @memcpy(copy_b[0..src.len], src);
    var r = try Reader.init(copy_a[0..src.len]);
    const cr: *const Reader = &r;
    try testing.expectEqual(@as(u16, 30), cr.count());
    for (0..11) |i| {
        const s = (try r.next()).?;
        try testing.expectEqual(@as(i64, @intCast(i * 10)), s.ts);
    }
    @memset(copy_a[0..src.len], 0xFF);
    r.rebind(copy_b[0..src.len]);
    for (11..30) |i| {
        const s = (try r.next()).?;
        try testing.expectEqual(@as(i64, @intCast(i * 10)), s.ts);
        try testing.expectEqual(@as(f64, @floatFromInt(i * i)), s.value);
    }
    try testing.expect((try r.next()) == null);
}
