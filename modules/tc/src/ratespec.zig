// SPDX-License-Identifier: MIT
//! psched clock parameters, `struct tc_ratespec` and the classic **rate
//! table** computation shared by the shaping qdiscs (htb, tbf).
//!
//! Rate-limited qdiscs do not carry a rate in bytes/s alone: alongside it
//! they carry a 256-entry lookup table mapping a packet size (in `1 <<
//! cell_log` byte cells) to the time it takes to transmit at that rate,
//! expressed in **psched ticks**. Kernels since v3.8 no longer use the table
//! for lookups, but `tc` still computes and sends it and the kernel still
//! validates its presence, so a byte-compatible client must reproduce it
//! exactly — including iproute2's floating-point rounding.
//!
//! The tick↔microsecond ratio comes from `/proc/net/psched`
//! (`t2us us2t clock_res tfsc`, four hex words). Everything here is a pure
//! function of a `Psched` value so the goldens are host-independent; only
//! `Psched.read` touches the filesystem.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const native_endian = builtin.cpu.arch.endian();

/// `TIME_UNITS_PER_SEC` — iproute2 expresses "time" in microseconds.
pub const time_units_per_sec: f64 = 1_000_000;

/// `enum link_layer` (iproute2 `tc/tc_core.h`); the low 4 bits land in
/// `tc_ratespec.linklayer`.
pub const LinkLayer = enum(u8) {
    unspec = 0,
    ethernet = 1,
    atm = 2,

    /// `TC_LINKLAYER_MASK`.
    pub const mask: u8 = 0x0F;
};

/// ATM SAR constants (`linux/atm.h`) used by the ATM size adjustment.
const atm_cell_payload: u32 = 48;
const atm_cell_size: u32 = 53;

/// The kernel's packet-scheduler clock calibration, as `tc` reads it from
/// `/proc/net/psched`.
///
/// The ticks-per-microsecond ratio is kept as an **exact rational**
/// (`tick_num / tick_den`) rather than a `f64`. iproute2 computes it in
/// floating point — `ceil(1e6 * (size/rate) * tick_in_usec)` — which is
/// evaluated in 80-bit x87 registers on its (still common) i386 builds and in
/// 64-bit SSE registers on x86-64, and those two disagree by one tick on
/// inputs where `size/rate` is not exactly representable (e.g. 984 B at
/// 125000 B/s: 123000 vs 123001). Doing the same arithmetic exactly in
/// integers gives the mathematically correct ceiling, which is what the
/// higher-precision build produces — see SPEC.md.
///
/// * `tick_num`/`tick_den` — how many psched ticks one microsecond is worth;
///   every `*_TIME` field on the wire (htb buffer/cbuffer, tbf buffer/mtu,
///   the rate tables) is in these ticks.
/// * `hz` — the scheduler frequency iproute2 derives from the same file; used
///   only to pick a default burst (`rate / hz + mtu`).
pub const Psched = struct {
    tick_num: u64,
    tick_den: u64,
    hz: u64,

    /// iproute2's fallback when `/proc/net/psched` is missing: one tick per
    /// microsecond, and `hz` falls back to `HZ` (`sysconf(_SC_CLK_TCK)` = 100
    /// on every mainstream Linux build).
    pub const fallback: Psched = .{ .tick_num = 1, .tick_den = 1, .hz = 100 };

    /// Derive the calibration from the four hex words of `/proc/net/psched`,
    /// mirroring iproute2's `tc_core_init` + `__get_hz`:
    ///
    /// ```text
    /// if (clock_res == 1000000000) t2us = us2t;   // ns-resolution compat hack
    /// clock_factor = clock_res / 1e6
    /// tick_in_usec = t2us / us2t * clock_factor
    /// hz           = (clock_res == 1000000) ? tfsc : 100
    /// ```
    pub fn fromFields(t2us_in: u32, us2t: u32, clock_res: u32, tfsc: u32) Psched {
        if (us2t == 0 or clock_res == 0) return fallback;
        var t2us = t2us_in;
        // The kernel advertises a tick multiplier of 1000 for nanosecond
        // resolution, which really means 1.
        if (clock_res == 1_000_000_000) t2us = us2t;
        if (t2us == 0) return fallback;
        return .{
            // tick_in_usec = (t2us / us2t) * (clock_res / 1e6)
            .tick_num = @as(u64, t2us) * @as(u64, clock_res),
            .tick_den = @as(u64, us2t) * 1_000_000,
            .hz = if (clock_res == 1_000_000) tfsc else 100,
        };
    }

    /// The calibration as iproute2 keeps it, for printing and for the
    /// non-wire `tick2time`/`calcXmitSize` conversions.
    pub fn tickInUsec(ps: Psched) f64 {
        return @as(f64, @floatFromInt(ps.tick_num)) / @as(f64, @floatFromInt(ps.tick_den));
    }

    /// Parse the raw text of `/proc/net/psched` (four whitespace-separated
    /// hex words). Returns null when the file does not have that shape.
    pub fn parse(text: []const u8) ?Psched {
        var words: [4]u32 = undefined;
        var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
        for (&words) |*w| {
            const tok = it.next() orelse return null;
            w.* = std.fmt.parseInt(u32, tok, 16) catch return null;
        }
        return fromFields(words[0], words[1], words[2], words[3]);
    }

    /// Read the live calibration from `/proc/net/psched`, falling back to
    /// `Psched.fallback` when the file is missing or unreadable (a container
    /// with a hidden `/proc`, a non-Linux build). Never fails: an approximate
    /// calibration still produces a working — if not byte-identical to `tc` —
    /// request.
    pub fn read() Psched {
        if (comptime builtin.os.tag != .linux) return fallback;
        var buf: [128]u8 = undefined;
        const rc = linux.open("/proc/net/psched", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(rc) != .SUCCESS) return fallback;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        const n = linux.read(fd, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) return fallback;
        return parse(buf[0..n]) orelse fallback;
    }

    /// iproute2 `tc_core_time2tick`: microseconds → psched ticks.
    pub fn time2tick(ps: Psched, time_usec: f64) f64 {
        return time_usec * ps.tickInUsec();
    }

    /// iproute2 `tc_core_tick2time`: psched ticks → microseconds.
    pub fn tick2time(ps: Psched, ticks: f64) f64 {
        return ticks / ps.tickInUsec();
    }

    /// iproute2 `tc_calc_xmittime`: the time (in psched ticks) it takes to
    /// send `size` bytes at `rate` bytes/second, **rounded up**, saturating
    /// at `UINT_MAX`.
    ///
    /// ```text
    /// ticks = ceil(1e6 * size/rate * tick_num/tick_den)
    ///       = ceil(size * 1e6 * tick_num / (rate * tick_den))
    /// ```
    ///
    /// evaluated exactly in `u128` (see the `Psched` doc comment for why the
    /// floating-point form is not good enough).
    pub fn calcXmitTime(ps: Psched, rate: u64, size: u64) u32 {
        if (rate == 0) return std.math.maxInt(u32);
        const num = std.math.mul(u128, @as(u128, size), @as(u128, 1_000_000)) catch
            return std.math.maxInt(u32);
        const num2 = std.math.mul(u128, num, @as(u128, ps.tick_num)) catch
            return std.math.maxInt(u32);
        const den = std.math.mul(u128, @as(u128, rate), @as(u128, ps.tick_den)) catch
            return std.math.maxInt(u32);
        if (den == 0) return std.math.maxInt(u32);
        const ticks = (num2 + den - 1) / den; // ceiling division
        if (ticks > std.math.maxInt(u32)) return std.math.maxInt(u32);
        return @intCast(ticks);
    }

    /// iproute2 `tc_calc_xmitsize`: the inverse — how many bytes fit in
    /// `ticks` at `rate` bytes/second (rounded down). Used when decoding a
    /// dumped buffer/burst back into bytes.
    pub fn calcXmitSize(ps: Psched, rate: u64, ticks: u32) u64 {
        if (ps.tick_num == 0) return 0;
        const num = @as(u128, rate) * @as(u128, ticks) * @as(u128, ps.tick_den);
        const den = @as(u128, ps.tick_num) * 1_000_000;
        if (den == 0) return 0;
        const bytes = num / den;
        return @intCast(@min(bytes, std.math.maxInt(u64)));
    }
};

/// `struct tc_ratespec` (linux/pkt_sched.h) — 12 bytes, host byte order.
pub const RateSpec = struct {
    /// Packet sizes are looked up in the rate table in `1 << cell_log` byte
    /// cells; `calcRateTable` fills this in.
    cell_log: u8 = 0,
    linklayer: u8 = @intFromEnum(LinkLayer.ethernet),
    /// Per-packet link overhead in bytes (`tc … overhead N`).
    overhead: u16 = 0,
    /// Always -1 after a table computation (iproute2 sets it unconditionally).
    cell_align: i16 = -1,
    /// Minimum packet unit — sizes below this are billed as `mpu` bytes.
    mpu: u16 = 0,
    /// Rate in **bytes per second**, clamped to `~0U` when the real rate
    /// needs the 64-bit companion attribute.
    rate: u32 = 0,

    pub const wire_len = 12;

    pub fn encode(r: RateSpec) [wire_len]u8 {
        var out: [wire_len]u8 = undefined;
        out[0] = r.cell_log;
        out[1] = r.linklayer;
        std.mem.writeInt(u16, out[2..4], r.overhead, native_endian);
        std.mem.writeInt(i16, out[4..6], r.cell_align, native_endian);
        std.mem.writeInt(u16, out[6..8], r.mpu, native_endian);
        std.mem.writeInt(u32, out[8..12], r.rate, native_endian);
        return out;
    }

    pub fn decode(b: *const [wire_len]u8) RateSpec {
        return .{
            .cell_log = b[0],
            .linklayer = b[1],
            .overhead = std.mem.readInt(u16, b[2..4], native_endian),
            .cell_align = std.mem.readInt(i16, b[4..6], native_endian),
            .mpu = std.mem.readInt(u16, b[6..8], native_endian),
            .rate = std.mem.readInt(u32, b[8..12], native_endian),
        };
    }
};

/// Number of entries in a rate table (`TCA_HTB_RTAB`, `TCA_TBF_RTAB`, …).
pub const rate_table_entries = 256;
/// Wire size of one rate table.
pub const rate_table_len = rate_table_entries * 4;

/// iproute2 `tc_adjust_size`: raise a size to `mpu` and apply the link
/// layer's framing tax.
fn adjustSize(sz_in: u32, mpu: u32, linklayer: LinkLayer) u32 {
    const sz = @max(sz_in, mpu);
    return switch (linklayer) {
        .atm => blk: {
            var cells = sz / atm_cell_payload;
            if (sz % atm_cell_payload > 0) cells += 1;
            break :blk cells * atm_cell_size;
        },
        else => sz,
    };
}

/// Pick the cell shift the way iproute2 does when the caller did not force
/// one: the smallest shift for which `mtu >> cell_log` fits a 256-entry
/// table. `mtu == 0` means "use iproute2's 2047 default".
pub fn deriveCellLog(mtu_in: u32) u8 {
    const mtu = if (mtu_in == 0) 2047 else mtu_in;
    var cell_log: u8 = 0;
    while ((mtu >> @intCast(cell_log)) > 255) cell_log += 1;
    return cell_log;
}

/// iproute2 `tc_calc_rtable`: fill a 256-entry transmit-time table and patch
/// `spec`'s `cell_log`/`cell_align`/`linklayer` to match. `rate_override`
/// lets a caller compute the table from a rate other than `spec.rate` — htb
/// and tbf deliberately use the **clamped 32-bit** `spec.rate` even when the
/// real rate needs `RATE64`, so pass null to follow them.
pub fn calcRateTable(
    ps: Psched,
    spec: *RateSpec,
    table: *[rate_table_entries]u32,
    cell_log_override: ?u8,
    mtu: u32,
    linklayer: LinkLayer,
    rate_override: ?u64,
) void {
    const cell_log = cell_log_override orelse deriveCellLog(mtu);
    const bps: u64 = rate_override orelse spec.rate;
    for (table, 0..) |*e, i| {
        const raw: u32 = @as(u32, @intCast(i + 1)) << @intCast(cell_log);
        const sz = adjustSize(raw, spec.mpu, linklayer);
        e.* = ps.calcXmitTime(bps, sz);
    }
    spec.cell_align = -1;
    spec.cell_log = cell_log;
    spec.linklayer = @intFromEnum(linklayer) & LinkLayer.mask;
}

/// Serialize a rate table into its 1024-byte wire form (host byte order).
pub fn encodeRateTable(table: *const [rate_table_entries]u32) [rate_table_len]u8 {
    var out: [rate_table_len]u8 = undefined;
    for (table, 0..) |v, i| std.mem.writeInt(u32, out[i * 4 ..][0..4], v, native_endian);
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The calibration of the machine the goldens in `goldens.zig` were captured
/// on: `/proc/net/psched` = `000003e8 00000040 000f4240 3b9aca00`, i.e.
/// t2us=1000, us2t=64, clock_res=1e6, tfsc=1e9 → 15.625 ticks/µs, hz = 1e9.
pub const golden_psched: Psched = Psched.fromFields(0x3e8, 0x40, 0x000f4240, 0x3b9aca00);

test "Psched.fromFields reproduces the golden host's calibration" {
    try testing.expectEqual(@as(f64, 15.625), golden_psched.tickInUsec());
    try testing.expectEqual(@as(u64, 1_000_000_000), golden_psched.hz);
}

test "Psched.parse accepts the /proc/net/psched text form" {
    const ps = Psched.parse("000003e8 00000040 000f4240 3b9aca00\n").?;
    try testing.expectEqual(@as(f64, 15.625), ps.tickInUsec());
    try testing.expectEqual(@as(u64, 1_000_000_000), ps.hz);
    try testing.expectEqual(@as(?Psched, null), Psched.parse("garbage"));
    try testing.expectEqual(@as(?Psched, null), Psched.parse("1 2 3"));
}

test "Psched.fromFields applies the nanosecond-resolution compat hack" {
    // clock_res == 1e9 → the advertised t2us is bogus and equals us2t.
    const ps = Psched.fromFields(1000, 1, 1_000_000_000, 0);
    try testing.expectEqual(@as(f64, 1000), ps.tickInUsec()); // 1/1 * 1e9/1e6
    try testing.expectEqual(@as(u64, 100), ps.hz); // clock_res != 1e6 → HZ
    // Degenerate divisor must not produce a NaN calibration.
    try testing.expectEqual(Psched.fallback.tickInUsec(), Psched.fromFields(1, 0, 0, 0).tickInUsec());
}

test "calcXmitTime rounds up, exactly like tc_calc_xmittime" {
    const ps = golden_psched;
    // 8 bytes at 125000 B/s = 64 µs = 1000 ticks, exact.
    try testing.expectEqual(@as(u32, 1000), ps.calcXmitTime(125_000, 8));
    // 8 bytes at 1.25 GB/s = 0.0064 µs = 0.1 ticks → 1 (ceil, not 0).
    try testing.expectEqual(@as(u32, 1), ps.calcXmitTime(1_250_000_000, 8));
    // 2048 bytes at 1.25 GB/s = 1.6384 µs = 25.6 ticks → 26.
    try testing.expectEqual(@as(u32, 26), ps.calcXmitTime(1_250_000_000, 2048));
    // 1600 bytes at 125000 B/s → 12800 µs → 200000 ticks (htb's default burst).
    try testing.expectEqual(@as(u32, 200_000), ps.calcXmitTime(125_000, 1600));
    // Saturation instead of a wrap.
    try testing.expectEqual(std.math.maxInt(u32), ps.calcXmitTime(1, std.math.maxInt(u64)));
    try testing.expectEqual(std.math.maxInt(u32), ps.calcXmitTime(0, 1));
}

test "deriveCellLog matches iproute2's mtu-driven shift" {
    try testing.expectEqual(@as(u8, 3), deriveCellLog(1600));
    try testing.expectEqual(@as(u8, 3), deriveCellLog(1500));
    try testing.expectEqual(@as(u8, 3), deriveCellLog(2047)); // the mtu==0 default
    try testing.expectEqual(@as(u8, 3), deriveCellLog(0));
    try testing.expectEqual(@as(u8, 5), deriveCellLog(4096)); // 4096>>4 = 256 > 255
    try testing.expectEqual(@as(u8, 0), deriveCellLog(255));
}

test "calcRateTable reproduces tc's tables for the captured rates" {
    const ps = golden_psched;
    var table: [rate_table_entries]u32 = undefined;

    // `htb rate 1mbit` → 125000 B/s, mtu 1600, ethernet.
    var spec: RateSpec = .{ .rate = 125_000 };
    calcRateTable(ps, &spec, &table, null, 1600, .ethernet, null);
    try testing.expectEqual(@as(u8, 3), spec.cell_log);
    try testing.expectEqual(@as(i16, -1), spec.cell_align);
    try testing.expectEqual(@as(u8, 1), spec.linklayer);
    for (table, 0..) |v, i| try testing.expectEqual(@as(u32, 1000) * @as(u32, @intCast(i + 1)), v);

    // `ceil 2mbit` → 250000 B/s: exactly half the transmit time.
    spec = .{ .rate = 250_000 };
    calcRateTable(ps, &spec, &table, null, 1600, .ethernet, null);
    for (table, 0..) |v, i| try testing.expectEqual(@as(u32, 500) * @as(u32, @intCast(i + 1)), v);

    // `rate 40gbit` → clamped to ~0U for the table (see `rate_override`).
    spec = .{ .rate = std.math.maxInt(u32) };
    calcRateTable(ps, &spec, &table, null, 1600, .ethernet, null);
    try testing.expectEqual(@as(u32, 1), table[0]);
    try testing.expectEqual(@as(u32, 8), table[255]);

    // `mtu 1500 rate 5mbit` → 625000 B/s, still cell_log 3.
    spec = .{ .rate = 625_000 };
    calcRateTable(ps, &spec, &table, null, 1500, .ethernet, null);
    try testing.expectEqual(@as(u32, 200), table[0]);
    try testing.expectEqual(@as(u32, 51_200), table[255]);
}

test "ATM link layer applies the SAR cell tax" {
    // 48-byte payload cells framed into 53-byte cells: 8 B → 1 cell → 53 B.
    try testing.expectEqual(@as(u32, 53), adjustSize(8, 0, .atm));
    try testing.expectEqual(@as(u32, 53), adjustSize(48, 0, .atm));
    try testing.expectEqual(@as(u32, 106), adjustSize(49, 0, .atm));
    try testing.expectEqual(@as(u32, 8), adjustSize(8, 0, .ethernet));
    try testing.expectEqual(@as(u32, 64), adjustSize(8, 64, .ethernet)); // mpu floor
}

test "RateSpec encode/decode round-trip and byte layout" {
    const spec: RateSpec = .{
        .cell_log = 3,
        .linklayer = 1,
        .overhead = 0,
        .cell_align = -1,
        .mpu = 0,
        .rate = 125_000,
    };
    const enc = spec.encode();
    if (native_endian == .little) {
        // Byte-for-byte the tc_ratespec captured from `tc class add … rate 1mbit`.
        try testing.expectEqualSlices(u8, &.{
            0x03, 0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x48, 0xe8, 0x01, 0x00,
        }, &enc);
    }
    const back = RateSpec.decode(&enc);
    try testing.expectEqual(spec, back);
}

test "calcXmitSize inverts calcXmitTime closely enough to print a burst" {
    const ps = golden_psched;
    try testing.expectEqual(@as(u64, 1600), ps.calcXmitSize(125_000, 200_000));
    try testing.expectEqual(@as(u64, 4096), ps.calcXmitSize(125_000, 512_000));
}
