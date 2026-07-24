// SPDX-License-Identifier: MIT
//! Qdisc and class option encoding/decoding: the kind-specific `TCA_OPTIONS`
//! payloads for **netem**, **htb**, **tbf** and **fq_codel**.
//!
//! Everything here is pure: a spec struct in ergonomic units goes in, wire
//! bytes come out, and a `TCA_OPTIONS` payload read back from a dump decodes
//! into a `*Wire` struct carrying the raw kernel values. No syscalls, so the
//! whole layer is golden-testable offline against bytes captured from
//! iproute2 (see `goldens.zig`).

const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
const codec = netlink.codec;

const ratespec = @import("ratespec.zig");
const Psched = ratespec.Psched;
const RateSpec = ratespec.RateSpec;
const LinkLayer = ratespec.LinkLayer;

const handle_mod = @import("handle.zig");
const Handle = handle_mod.Handle;

// ── attribute-type constants (kernel UAPI) ──────────────────────────────────

/// Qdisc/class attribute types (linux/rtnetlink.h `TCA_*`) — attributes on
/// the `tcmsg` fixed header.
pub const TCA = struct {
    pub const UNSPEC: u16 = 0;
    pub const KIND: u16 = 1;
    pub const OPTIONS: u16 = 2;
    pub const STATS: u16 = 3;
    pub const XSTATS: u16 = 4;
    pub const RATE: u16 = 5;
    pub const FCNT: u16 = 6;
    pub const STATS2: u16 = 7;
    pub const STAB: u16 = 8;
    pub const PAD: u16 = 9;
    pub const DUMP_INVISIBLE: u16 = 10;
    pub const CHAIN: u16 = 11;
    pub const HW_OFFLOAD: u16 = 12;
    pub const INGRESS_BLOCK: u16 = 13;
    pub const EGRESS_BLOCK: u16 = 14;
};

/// netem extended attribute types (linux/pkt_sched.h `TCA_NETEM_*`).
pub const TCA_NETEM = struct {
    pub const UNSPEC: u16 = 0;
    pub const CORR: u16 = 1;
    pub const DELAY_DIST: u16 = 2;
    pub const REORDER: u16 = 3;
    pub const CORRUPT: u16 = 4;
    pub const LOSS: u16 = 5;
    pub const RATE: u16 = 6;
    pub const ECN: u16 = 7;
    pub const RATE64: u16 = 8;
    pub const PAD: u16 = 9;
    pub const LATENCY64: u16 = 10;
    pub const JITTER64: u16 = 11;
};

/// htb attribute types (linux/pkt_sched.h `TCA_HTB_*`).
pub const TCA_HTB = struct {
    pub const UNSPEC: u16 = 0;
    pub const PARMS: u16 = 1;
    pub const INIT: u16 = 2;
    pub const CTAB: u16 = 3;
    pub const RTAB: u16 = 4;
    pub const DIRECT_QLEN: u16 = 5;
    pub const RATE64: u16 = 6;
    pub const CEIL64: u16 = 7;
    pub const PAD: u16 = 8;
    pub const OFFLOAD: u16 = 9;
};

/// tbf attribute types (linux/pkt_sched.h `TCA_TBF_*`).
pub const TCA_TBF = struct {
    pub const UNSPEC: u16 = 0;
    pub const PARMS: u16 = 1;
    pub const RTAB: u16 = 2;
    pub const PTAB: u16 = 3;
    pub const RATE64: u16 = 4;
    pub const PRATE64: u16 = 5;
    pub const BURST: u16 = 6;
    pub const PBURST: u16 = 7;
    pub const PAD: u16 = 8;
};

/// fq_codel attribute types (linux/pkt_sched.h `TCA_FQ_CODEL_*`).
pub const TCA_FQ_CODEL = struct {
    pub const UNSPEC: u16 = 0;
    pub const TARGET: u16 = 1;
    pub const LIMIT: u16 = 2;
    pub const INTERVAL: u16 = 3;
    pub const ECN: u16 = 4;
    pub const FLOWS: u16 = 5;
    pub const QUANTUM: u16 = 6;
    pub const CE_THRESHOLD: u16 = 7;
    pub const DROP_BATCH_SIZE: u16 = 8;
    pub const MEMORY_LIMIT: u16 = 9;
    pub const CE_THRESHOLD_SELECTOR: u16 = 10;
    pub const CE_THRESHOLD_MASK: u16 = 11;
};

/// cake attribute types (linux/pkt_sched.h `TCA_CAKE_*`).
pub const TCA_CAKE = struct {
    pub const UNSPEC: u16 = 0;
    pub const PAD: u16 = 1;
    pub const BASE_RATE64: u16 = 2;
    pub const DIFFSERV_MODE: u16 = 3;
    pub const ATM: u16 = 4;
    pub const FLOW_MODE: u16 = 5;
    pub const OVERHEAD: u16 = 6;
    pub const RTT: u16 = 7;
    pub const TARGET: u16 = 8;
    pub const AUTORATE: u16 = 9;
    pub const MEMORY: u16 = 10;
    pub const NAT: u16 = 11;
    pub const RAW: u16 = 12;
    pub const WASH: u16 = 13;
    pub const MPU: u16 = 14;
    pub const INGRESS: u16 = 15;
    pub const ACK_FILTER: u16 = 16;
    pub const SPLIT_GSO: u16 = 17;
    pub const FWMARK: u16 = 18;
};

pub const kind_netem = "netem";
pub const kind_htb = "htb";
pub const kind_tbf = "tbf";
pub const kind_fq_codel = "fq_codel";
pub const kind_mq = "mq";
pub const kind_cake = "cake";

/// `sizeof(struct tc_netem_qopt)`.
pub const tc_netem_qopt_len = 24;
/// `sizeof(struct tc_htb_glob)` — version, rate2quantum, defcls, debug,
/// direct_pkts.
pub const tc_htb_glob_len = 20;
/// `sizeof(struct tc_htb_opt)` — two tc_ratespecs + buffer/cbuffer/quantum/
/// level/prio.
pub const tc_htb_opt_len = 44;
/// `sizeof(struct tc_tbf_qopt)` — two tc_ratespecs + limit/buffer/mtu.
pub const tc_tbf_qopt_len = 36;
/// `TC_HTB_PROTOVER` — the only version the kernel accepts.
pub const htb_protover: u32 = 3;

// ── errors ──────────────────────────────────────────────────────────────────

pub const EncodeError = std.mem.Allocator.Error || error{
    /// A `*_pct` field outside `[0, 100]` (or NaN).
    InvalidPercent,
    /// A delay/jitter nanosecond value that does not fit the signed 64-bit
    /// wire field.
    InvalidDelay,
    /// A shaping qdisc/class with `rate == 0`.
    MissingRate,
    /// `tbf` without a `burst` — the kernel has no sensible default.
    MissingBurst,
    /// `tbf` with neither `limit` nor `latency_us`.
    MissingLimit,
    /// `tbf` with a `peakrate` but no `mtu` (needed for the peak burst).
    MissingMtu,
    /// A pre-encoded `raw` payload longer than one netlink attribute.
    OptionsTooLong,
};

// ── netem ───────────────────────────────────────────────────────────────────

/// A netem configuration, in ergonomic units (nanoseconds, percent 0..100).
/// See SPEC.md for the exact `tc_netem_qopt` + extended-attribute layout and
/// the psched-tick decision.
///
/// All `*_pct` fields are percentages in `[0, 100]`; encoding returns
/// `error.InvalidPercent` for anything outside that range (including NaN).
pub const Netem = struct {
    /// FIFO packet limit ("tc … limit N"); the kernel/tc default is 1000.
    limit: u32 = 1000,
    /// Base one-way added delay ("delay Xms"), nanoseconds. 0 = no delay.
    /// Encoded via `TCA_NETEM_LATENCY64`, never the legacy psched-tick
    /// `tc_netem_qopt.latency` field.
    delay_ns: u64 = 0,
    /// Delay jitter ("delay Xms Yms"), nanoseconds. Encoded via
    /// `TCA_NETEM_JITTER64`.
    jitter_ns: u64 = 0,
    /// Delay correlation percent ("delay Xms Yms Z%").
    delay_correlation_pct: f64 = 0,
    /// Random packet loss probability percent ("loss Z%").
    loss_pct: f64 = 0,
    /// Loss correlation percent ("loss Z% W%").
    loss_correlation_pct: f64 = 0,
    /// Random packet duplication probability percent ("duplicate Z%").
    duplicate_pct: f64 = 0,
    /// Duplicate correlation percent.
    duplicate_correlation_pct: f64 = 0,
    /// Random reordering probability percent ("reorder Z%").
    reorder_pct: f64 = 0,
    /// Reorder correlation percent.
    reorder_correlation_pct: f64 = 0,
    /// Deterministic reorder gap ("reorder … gap N"): every Nth packet
    /// bypasses the delay queue. 0 = off (probabilistic reorder only).
    reorder_gap: u32 = 0,
    /// Random packet corruption probability percent ("corrupt Z%").
    corrupt_pct: f64 = 0,
    /// Corrupt correlation percent.
    corrupt_correlation_pct: f64 = 0,
    /// Rate limit in bytes/s ("rate Rbit/Rbps"). 0 = unlimited. Only
    /// `TCA_NETEM_RATE` (u32) is emitted; `TCA_NETEM_RATE64` is out of scope.
    rate_bytes_per_sec: u32 = 0,
};

/// Wire-level readback of a netem qdisc's options. Deliberately separate from
/// `Netem`: these are the raw scaled/kernel values (no percent
/// reconstruction — avoids float round-trip ambiguity).
pub const NetemWire = struct {
    limit: u32 = 0,
    /// Raw scaled probability (`percent/100 * UINT32_MAX`), 0 = none.
    loss: u32 = 0,
    duplicate: u32 = 0,
    /// `tc_netem_qopt.gap` — the deterministic reorder gap.
    gap: u32 = 0,
    /// Legacy `tc_netem_qopt.latency`/`.jitter` fields. This module always
    /// writes 0 here; a dumping kernel may report a nonzero legacy value.
    legacy_latency: u32 = 0,
    legacy_jitter: u32 = 0,
    /// `TCA_NETEM_LATENCY64` / `TCA_NETEM_JITTER64`, nanoseconds; 0 if absent.
    delay_ns: i64 = 0,
    jitter_ns: i64 = 0,
    delay_correlation: u32 = 0,
    loss_correlation: u32 = 0,
    duplicate_correlation: u32 = 0,
    reorder_probability: u32 = 0,
    reorder_correlation: u32 = 0,
    corrupt_probability: u32 = 0,
    corrupt_correlation: u32 = 0,
    /// `TCA_NETEM_RATE.rate` (bytes/s); 0 if absent.
    rate_bytes_per_sec: u32 = 0,
};

/// Scale a `[0, 100]` percent to the kernel's `u32` probability scale
/// (`percent/100 * UINT32_MAX`, rounded — matches `tc`'s own scaling).
pub fn percentToU32(pct: f64) error{InvalidPercent}!u32 {
    if (!(pct >= 0.0 and pct <= 100.0)) return error.InvalidPercent;
    const scaled = @round(pct / 100.0 * @as(f64, @floatFromInt(std.math.maxInt(u32))));
    return @intFromFloat(scaled);
}

fn checkDelayNs(ns: u64) error{InvalidDelay}!void {
    if (ns > std.math.maxInt(i64)) return error.InvalidDelay;
}

fn appendNetemOptions(
    n: Netem,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) EncodeError!void {
    // Validate + pre-scale every percent field before touching the buffer.
    const loss = try percentToU32(n.loss_pct);
    const loss_corr = try percentToU32(n.loss_correlation_pct);
    const dup = try percentToU32(n.duplicate_pct);
    const dup_corr = try percentToU32(n.duplicate_correlation_pct);
    const delay_corr = try percentToU32(n.delay_correlation_pct);
    const reorder_prob = try percentToU32(n.reorder_pct);
    const reorder_corr = try percentToU32(n.reorder_correlation_pct);
    const corrupt_prob = try percentToU32(n.corrupt_pct);
    const corrupt_corr = try percentToU32(n.corrupt_correlation_pct);
    try checkDelayNs(n.delay_ns);
    try checkDelayNs(n.jitter_ns);

    {
        // struct tc_netem_qopt: latency(0, real value via LATENCY64), limit,
        // loss, gap, duplicate, jitter(0, real value via JITTER64).
        var qopt: [tc_netem_qopt_len]u8 = @splat(0);
        std.mem.writeInt(u32, qopt[4..8], n.limit, native_endian);
        std.mem.writeInt(u32, qopt[8..12], loss, native_endian);
        std.mem.writeInt(u32, qopt[12..16], n.reorder_gap, native_endian);
        std.mem.writeInt(u32, qopt[16..20], dup, native_endian);
        try codec.appendPadded(gpa, list, &qopt); // already 4-aligned (24 B)
    }
    if (delay_corr != 0 or loss_corr != 0 or dup_corr != 0) {
        var corr: [12]u8 = undefined;
        std.mem.writeInt(u32, corr[0..4], delay_corr, native_endian);
        std.mem.writeInt(u32, corr[4..8], loss_corr, native_endian);
        std.mem.writeInt(u32, corr[8..12], dup_corr, native_endian);
        try appendAttr(gpa, list, TCA_NETEM.CORR, &corr);
    }
    if (reorder_prob != 0 or n.reorder_gap != 0) {
        var reo: [8]u8 = undefined;
        std.mem.writeInt(u32, reo[0..4], reorder_prob, native_endian);
        std.mem.writeInt(u32, reo[4..8], reorder_corr, native_endian);
        try appendAttr(gpa, list, TCA_NETEM.REORDER, &reo);
    }
    if (corrupt_prob != 0) {
        var cor: [8]u8 = undefined;
        std.mem.writeInt(u32, cor[0..4], corrupt_prob, native_endian);
        std.mem.writeInt(u32, cor[4..8], corrupt_corr, native_endian);
        try appendAttr(gpa, list, TCA_NETEM.CORRUPT, &cor);
    }
    if (n.rate_bytes_per_sec != 0) {
        // struct tc_netem_rate: rate, packet_overhead, cell_size,
        // cell_overhead — the overhead/cell knobs are out of scope.
        var rate: [16]u8 = @splat(0);
        std.mem.writeInt(u32, rate[0..4], n.rate_bytes_per_sec, native_endian);
        try appendAttr(gpa, list, TCA_NETEM.RATE, &rate);
    }
    if (n.delay_ns != 0) {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(i64, &raw, @intCast(n.delay_ns), native_endian);
        try appendAttr(gpa, list, TCA_NETEM.LATENCY64, &raw);
    }
    if (n.jitter_ns != 0) {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(i64, &raw, @intCast(n.jitter_ns), native_endian);
        try appendAttr(gpa, list, TCA_NETEM.JITTER64, &raw);
    }
}

/// Parse a `TCA_OPTIONS` payload for a netem qdisc: fixed `tc_netem_qopt`
/// (24 B) followed by extended `TCA_NETEM_*` TLVs. Sub-attributes with an
/// unexpected length are ignored rather than rejected — one odd attribute
/// shouldn't fail the whole parse.
pub fn parseNetemOptions(data: []const u8) codec.Error!NetemWire {
    if (data.len < tc_netem_qopt_len) return error.Truncated;
    var nw: NetemWire = .{
        .legacy_latency = std.mem.readInt(u32, data[0..4], native_endian),
        .limit = std.mem.readInt(u32, data[4..8], native_endian),
        .loss = std.mem.readInt(u32, data[8..12], native_endian),
        .gap = std.mem.readInt(u32, data[12..16], native_endian),
        .duplicate = std.mem.readInt(u32, data[16..20], native_endian),
        .legacy_jitter = std.mem.readInt(u32, data[20..24], native_endian),
    };
    var it: codec.AttrIterator = .{ .buf = data[tc_netem_qopt_len..] };
    while (try it.next()) |a| switch (a.type) {
        TCA_NETEM.CORR => if (a.data.len == 12) {
            nw.delay_correlation = std.mem.readInt(u32, a.data[0..4], native_endian);
            nw.loss_correlation = std.mem.readInt(u32, a.data[4..8], native_endian);
            nw.duplicate_correlation = std.mem.readInt(u32, a.data[8..12], native_endian);
        },
        TCA_NETEM.REORDER => if (a.data.len == 8) {
            nw.reorder_probability = std.mem.readInt(u32, a.data[0..4], native_endian);
            nw.reorder_correlation = std.mem.readInt(u32, a.data[4..8], native_endian);
        },
        TCA_NETEM.CORRUPT => if (a.data.len == 8) {
            nw.corrupt_probability = std.mem.readInt(u32, a.data[0..4], native_endian);
            nw.corrupt_correlation = std.mem.readInt(u32, a.data[4..8], native_endian);
        },
        TCA_NETEM.RATE => if (a.data.len >= 4) {
            nw.rate_bytes_per_sec = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        TCA_NETEM.LATENCY64 => if (a.data.len == 8) {
            nw.delay_ns = std.mem.readInt(i64, a.data[0..8], native_endian);
        },
        TCA_NETEM.JITTER64 => if (a.data.len == 8) {
            nw.jitter_ns = std.mem.readInt(i64, a.data[0..8], native_endian);
        },
        else => {},
    };
    return nw;
}

// ── htb ─────────────────────────────────────────────────────────────────────

/// The **qdisc**-level htb configuration (`struct tc_htb_glob`, sent as
/// `TCA_HTB_INIT`). Classes are configured separately with `HtbClass`.
pub const Htb = struct {
    /// `r2q` — divisor turning a class rate into its DRR quantum.
    rate2quantum: u32 = 10,
    /// `default N` — the class minor unclassified traffic falls into. Note
    /// `tc` parses this argument as **hexadecimal** (`default 10` = 0x10);
    /// this field is a plain number, so pass 0x10 to match `tc default 10`.
    defcls: u32 = 0,
    /// Kernel debug bitmap; leave 0.
    debug: u32 = 0,
    /// Out-only counter in the kernel's dump; leave 0 on a request.
    direct_pkts: u32 = 0,
    /// `direct_qlen N` — queue length of the direct (unshaped) path. null
    /// omits the attribute, letting the kernel pick the device default.
    direct_qlen: ?u32 = null,
    /// `offload` — ask the driver to shape in hardware.
    offload: bool = false,
};

/// An htb **class**: a rate/ceil pair plus the burst sizing that turns them
/// into token buckets.
pub const HtbClass = struct {
    /// Guaranteed rate in **bytes per second** (`rate`). Required.
    rate: u64,
    /// Ceiling rate in bytes per second (`ceil`); 0 means "same as `rate`",
    /// exactly like `tc`.
    ceil: u64 = 0,
    /// `burst` in bytes; 0 derives `rate / psched.hz + mtu` like `tc`.
    burst: u32 = 0,
    /// `cburst` in bytes; 0 derives `ceil / psched.hz + mtu`.
    cburst: u32 = 0,
    /// DRR `quantum`; 0 lets the kernel derive it from `rate2quantum`.
    quantum: u32 = 0,
    /// Priority band (`prio`), lower = served first.
    prio: u32 = 0,
    /// Largest packet the rate tables are sized for (`mtu`). tc's default is
    /// 1600 ("eth packet len"), not the interface MTU.
    mtu: u32 = 1600,
    /// Minimum packet unit (`mpu`).
    mpu: u16 = 0,
    /// Per-packet link overhead in bytes (`overhead`).
    overhead: u16 = 0,
    /// Link layer used for the size adjustment (`linklayer`).
    linklayer: LinkLayer = .ethernet,
    /// Force the rate table's cell shift; null derives it from `mtu`.
    cell_log: ?u8 = null,
    /// Force the ceil table's cell shift; null derives it from `mtu`.
    ccell_log: ?u8 = null,
};

/// Wire readback of `TCA_HTB_PARMS` (+ the 64-bit rate companions).
pub const HtbClassWire = struct {
    rate: RateSpec = .{},
    ceil: RateSpec = .{},
    buffer: u32 = 0,
    cbuffer: u32 = 0,
    quantum: u32 = 0,
    level: u32 = 0,
    prio: u32 = 0,
    /// `TCA_HTB_RATE64`/`CEIL64` when present, else the 32-bit `rate`/`ceil`
    /// from the ratespecs — i.e. always the effective rate in bytes/s.
    rate64: u64 = 0,
    ceil64: u64 = 0,
};

/// Wire readback of `TCA_HTB_INIT` (the qdisc-level `tc_htb_glob`).
pub const HtbWire = struct {
    version: u32 = 0,
    rate2quantum: u32 = 0,
    defcls: u32 = 0,
    debug: u32 = 0,
    direct_pkts: u32 = 0,
    direct_qlen: ?u32 = null,
};

fn appendHtbOptions(h: Htb, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    var glob: [tc_htb_glob_len]u8 = @splat(0);
    std.mem.writeInt(u32, glob[0..4], htb_protover, native_endian);
    std.mem.writeInt(u32, glob[4..8], h.rate2quantum, native_endian);
    std.mem.writeInt(u32, glob[8..12], h.defcls, native_endian);
    std.mem.writeInt(u32, glob[12..16], h.debug, native_endian);
    std.mem.writeInt(u32, glob[16..20], h.direct_pkts, native_endian);
    try appendAttr(gpa, list, TCA_HTB.INIT, &glob);
    if (h.direct_qlen) |q| try codec.appendAttrU32(gpa, list, TCA_HTB.DIRECT_QLEN, q);
    if (h.offload) try appendAttr(gpa, list, TCA_HTB.OFFLOAD, &.{});
}

/// Clamp a 64-bit rate into a `tc_ratespec.rate`, the way `tc` does: rates
/// that need more than 32 bits are pinned to `~0U` and carried in the
/// companion `*_RATE64` attribute instead.
fn clampRate(rate: u64) u32 {
    return if (rate >= (1 << 32)) std.math.maxInt(u32) else @intCast(rate);
}

fn appendHtbClassOptions(
    c: HtbClass,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    if (c.rate == 0) return error.MissingRate;
    const rate64 = c.rate;
    const ceil64 = if (c.ceil == 0) rate64 else c.ceil;

    var rate_spec: RateSpec = .{
        .rate = clampRate(rate64),
        .mpu = c.mpu,
        .overhead = c.overhead,
    };
    var ceil_spec: RateSpec = .{
        .rate = clampRate(ceil64),
        .mpu = c.mpu,
        .overhead = c.overhead,
    };

    // "compute minimal allowed burst from rate; mtu is added to make sure
    // that buffer is larger than mtu and to have some safeguard space"
    const hz = if (ps.hz == 0) 1 else ps.hz;
    const burst: u64 = if (c.burst != 0) c.burst else rate64 / hz + c.mtu;
    const cburst: u64 = if (c.cburst != 0) c.cburst else ceil64 / hz + c.mtu;

    var rtab: [ratespec.rate_table_entries]u32 = undefined;
    var ctab: [ratespec.rate_table_entries]u32 = undefined;
    // NB: the tables are computed from the **clamped** 32-bit rate (tc calls
    // tc_calc_rtable, not tc_calc_rtable_64, for htb), while the buffer
    // timings use the full 64-bit rate. Reproduced faithfully.
    ratespec.calcRateTable(ps, &rate_spec, &rtab, c.cell_log, c.mtu, c.linklayer, null);
    const buffer_ticks = ps.calcXmitTime(rate64, burst);
    ratespec.calcRateTable(ps, &ceil_spec, &ctab, c.ccell_log, c.mtu, c.linklayer, null);
    const cbuffer_ticks = ps.calcXmitTime(ceil64, cburst);

    if (rate64 >= (1 << 32)) try appendAttrU64(gpa, list, TCA_HTB.RATE64, rate64);
    if (ceil64 >= (1 << 32)) try appendAttrU64(gpa, list, TCA_HTB.CEIL64, ceil64);

    var parms: [tc_htb_opt_len]u8 = @splat(0);
    parms[0..RateSpec.wire_len].* = rate_spec.encode();
    parms[RateSpec.wire_len..][0..RateSpec.wire_len].* = ceil_spec.encode();
    std.mem.writeInt(u32, parms[24..28], buffer_ticks, native_endian);
    std.mem.writeInt(u32, parms[28..32], cbuffer_ticks, native_endian);
    std.mem.writeInt(u32, parms[32..36], c.quantum, native_endian);
    std.mem.writeInt(u32, parms[36..40], 0, native_endian); // level: out-only
    std.mem.writeInt(u32, parms[40..44], c.prio, native_endian);
    try appendAttr(gpa, list, TCA_HTB.PARMS, &parms);

    const rtab_bytes = ratespec.encodeRateTable(&rtab);
    try appendAttr(gpa, list, TCA_HTB.RTAB, &rtab_bytes);
    const ctab_bytes = ratespec.encodeRateTable(&ctab);
    try appendAttr(gpa, list, TCA_HTB.CTAB, &ctab_bytes);
}

/// Parse an htb **qdisc**'s `TCA_OPTIONS` (`TCA_HTB_INIT` + friends).
pub fn parseHtbOptions(data: []const u8) codec.Error!HtbWire {
    var hw: HtbWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_HTB.INIT => if (a.data.len >= tc_htb_glob_len) {
            hw.version = std.mem.readInt(u32, a.data[0..4], native_endian);
            hw.rate2quantum = std.mem.readInt(u32, a.data[4..8], native_endian);
            hw.defcls = std.mem.readInt(u32, a.data[8..12], native_endian);
            hw.debug = std.mem.readInt(u32, a.data[12..16], native_endian);
            hw.direct_pkts = std.mem.readInt(u32, a.data[16..20], native_endian);
        },
        TCA_HTB.DIRECT_QLEN => if (a.data.len == 4) {
            hw.direct_qlen = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        else => {},
    };
    return hw;
}

/// Parse an htb **class**'s `TCA_OPTIONS` (`TCA_HTB_PARMS` + `RATE64`/
/// `CEIL64`). The 1 KiB rate tables are skipped: the kernel has not used them
/// for lookups since v3.8 and they carry no information the parms lack.
pub fn parseHtbClassOptions(data: []const u8) codec.Error!HtbClassWire {
    var cw: HtbClassWire = .{};
    var rate64: ?u64 = null;
    var ceil64: ?u64 = null;
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_HTB.PARMS => {
            if (a.data.len < tc_htb_opt_len) return error.BadLength;
            cw.rate = RateSpec.decode(a.data[0..RateSpec.wire_len]);
            cw.ceil = RateSpec.decode(a.data[RateSpec.wire_len..][0..RateSpec.wire_len]);
            cw.buffer = std.mem.readInt(u32, a.data[24..28], native_endian);
            cw.cbuffer = std.mem.readInt(u32, a.data[28..32], native_endian);
            cw.quantum = std.mem.readInt(u32, a.data[32..36], native_endian);
            cw.level = std.mem.readInt(u32, a.data[36..40], native_endian);
            cw.prio = std.mem.readInt(u32, a.data[40..44], native_endian);
        },
        TCA_HTB.RATE64 => if (a.data.len == 8) {
            rate64 = std.mem.readInt(u64, a.data[0..8], native_endian);
        },
        TCA_HTB.CEIL64 => if (a.data.len == 8) {
            ceil64 = std.mem.readInt(u64, a.data[0..8], native_endian);
        },
        else => {},
    };
    cw.rate64 = rate64 orelse cw.rate.rate;
    cw.ceil64 = ceil64 orelse cw.ceil.rate;
    return cw;
}

// ── tbf ─────────────────────────────────────────────────────────────────────

/// A token-bucket filter qdisc. Either `limit` or `latency_us` must be set;
/// `burst` is always required (`tc` refuses without it too).
pub const Tbf = struct {
    /// Sustained rate in **bytes per second** (`rate`). Required.
    rate: u64,
    /// Bucket size in bytes (`burst`/`buffer`). Required.
    burst: u32,
    /// Queue limit in bytes (`limit`). 0 derives it from `latency_us`.
    limit: u32 = 0,
    /// Target queueing latency in microseconds (`latency`), used only when
    /// `limit == 0`.
    latency_us: u32 = 0,
    /// Peak rate in bytes/second (`peakrate`); 0 disables the second bucket.
    peakrate: u64 = 0,
    /// Peak-bucket size in bytes (`mtu`/`minburst`). Required when
    /// `peakrate != 0`; also seeds the rate tables' cell shift.
    mtu: u32 = 0,
    mpu: u16 = 0,
    overhead: u16 = 0,
    linklayer: LinkLayer = .ethernet,
    /// Force the rate table's cell shift; null derives it from `mtu`.
    cell_log: ?u8 = null,
    /// Force the peak table's cell shift; null derives it from `mtu`.
    pcell_log: ?u8 = null,
};

/// Wire readback of `TCA_TBF_PARMS` (+ the 64-bit rate companions).
pub const TbfWire = struct {
    rate: RateSpec = .{},
    peakrate: RateSpec = .{},
    limit: u32 = 0,
    buffer: u32 = 0,
    mtu: u32 = 0,
    rate64: u64 = 0,
    prate64: u64 = 0,
    /// `TCA_TBF_BURST` / `TCA_TBF_PBURST` in bytes, when present.
    burst_bytes: ?u32 = null,
    pburst_bytes: ?u32 = null,
};

fn appendTbfOptions(
    t: Tbf,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ps: Psched,
) EncodeError!void {
    if (t.rate == 0) return error.MissingRate;
    if (t.burst == 0) return error.MissingBurst;
    if (t.limit == 0 and t.latency_us == 0) return error.MissingLimit;
    if (t.peakrate != 0 and t.mtu == 0) return error.MissingMtu;

    var rate_spec: RateSpec = .{
        .rate = clampRate(t.rate),
        .mpu = t.mpu,
        .overhead = t.overhead,
    };
    var peak_spec: RateSpec = .{
        .rate = clampRate(t.peakrate),
        .mpu = t.mpu,
        .overhead = t.overhead,
    };

    var limit: u32 = t.limit;
    if (limit == 0) {
        const latency: f64 = @floatFromInt(t.latency_us);
        var lim = @as(f64, @floatFromInt(t.rate)) * latency / ratespec.time_units_per_sec +
            @as(f64, @floatFromInt(t.burst));
        if (t.peakrate != 0) {
            const lim2 = @as(f64, @floatFromInt(t.peakrate)) * latency / ratespec.time_units_per_sec +
                @as(f64, @floatFromInt(t.mtu));
            if (lim2 < lim) lim = lim2;
        }
        limit = if (lim >= @as(f64, std.math.maxInt(u32))) std.math.maxInt(u32) else @intFromFloat(lim);
    }

    var rtab: [ratespec.rate_table_entries]u32 = undefined;
    ratespec.calcRateTable(ps, &rate_spec, &rtab, t.cell_log, t.mtu, t.linklayer, null);
    // NB: unlike htb, tbf times its buffer with the **clamped** rate.
    const buffer_ticks = ps.calcXmitTime(rate_spec.rate, t.burst);

    var ptab: [ratespec.rate_table_entries]u32 = undefined;
    var mtu_ticks: u32 = 0;
    if (peak_spec.rate != 0) {
        ratespec.calcRateTable(ps, &peak_spec, &ptab, t.pcell_log, t.mtu, t.linklayer, null);
        mtu_ticks = ps.calcXmitTime(peak_spec.rate, t.mtu);
    }

    var parms: [tc_tbf_qopt_len]u8 = @splat(0);
    parms[0..RateSpec.wire_len].* = rate_spec.encode();
    if (peak_spec.rate != 0) {
        parms[RateSpec.wire_len..][0..RateSpec.wire_len].* = peak_spec.encode();
    }
    std.mem.writeInt(u32, parms[24..28], limit, native_endian);
    std.mem.writeInt(u32, parms[28..32], buffer_ticks, native_endian);
    std.mem.writeInt(u32, parms[32..36], mtu_ticks, native_endian);
    try appendAttr(gpa, list, TCA_TBF.PARMS, &parms);

    try codec.appendAttrU32(gpa, list, TCA_TBF.BURST, t.burst);
    if (t.rate >= (1 << 32)) try appendAttrU64(gpa, list, TCA_TBF.RATE64, t.rate);
    const rtab_bytes = ratespec.encodeRateTable(&rtab);
    try appendAttr(gpa, list, TCA_TBF.RTAB, &rtab_bytes);
    if (peak_spec.rate != 0) {
        if (t.peakrate >= (1 << 32)) try appendAttrU64(gpa, list, TCA_TBF.PRATE64, t.peakrate);
        try codec.appendAttrU32(gpa, list, TCA_TBF.PBURST, t.mtu);
        const ptab_bytes = ratespec.encodeRateTable(&ptab);
        try appendAttr(gpa, list, TCA_TBF.PTAB, &ptab_bytes);
    }
}

pub fn parseTbfOptions(data: []const u8) codec.Error!TbfWire {
    var tw: TbfWire = .{};
    var rate64: ?u64 = null;
    var prate64: ?u64 = null;
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_TBF.PARMS => {
            if (a.data.len < tc_tbf_qopt_len) return error.BadLength;
            tw.rate = RateSpec.decode(a.data[0..RateSpec.wire_len]);
            tw.peakrate = RateSpec.decode(a.data[RateSpec.wire_len..][0..RateSpec.wire_len]);
            tw.limit = std.mem.readInt(u32, a.data[24..28], native_endian);
            tw.buffer = std.mem.readInt(u32, a.data[28..32], native_endian);
            tw.mtu = std.mem.readInt(u32, a.data[32..36], native_endian);
        },
        TCA_TBF.RATE64 => if (a.data.len == 8) {
            rate64 = std.mem.readInt(u64, a.data[0..8], native_endian);
        },
        TCA_TBF.PRATE64 => if (a.data.len == 8) {
            prate64 = std.mem.readInt(u64, a.data[0..8], native_endian);
        },
        TCA_TBF.BURST => if (a.data.len == 4) {
            tw.burst_bytes = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        TCA_TBF.PBURST => if (a.data.len == 4) {
            tw.pburst_bytes = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        else => {},
    };
    tw.rate64 = rate64 orelse tw.rate.rate;
    tw.prate64 = prate64 orelse tw.peakrate.rate;
    return tw;
}

// ── fq_codel ────────────────────────────────────────────────────────────────

/// A fair-queueing CoDel qdisc. Every field is optional: `null` omits the
/// attribute and keeps the kernel's default, exactly like leaving the
/// argument off a `tc` command line.
pub const FqCodel = struct {
    /// Hard packet limit across all flows (`limit`).
    limit: ?u32 = null,
    /// Number of flow buckets (`flows`).
    flows: ?u32 = null,
    /// Bytes served per flow per round (`quantum`).
    quantum: ?u32 = null,
    /// CoDel interval in microseconds (`interval`).
    interval_us: ?u32 = null,
    /// CoDel target delay in microseconds (`target`).
    target_us: ?u32 = null,
    /// Enable ECN marking instead of dropping (`ecn`/`noecn`).
    ecn: ?bool = null,
    /// CE-threshold in microseconds (`ce_threshold`).
    ce_threshold_us: ?u32 = null,
    /// Total queue memory budget in bytes (`memory_limit`).
    memory_limit: ?u32 = null,
    /// Packets dropped per drop round (`drop_batch`).
    drop_batch: ?u32 = null,
};

/// Wire readback of an fq_codel qdisc's options.
pub const FqCodelWire = struct {
    limit: ?u32 = null,
    flows: ?u32 = null,
    quantum: ?u32 = null,
    interval_us: ?u32 = null,
    target_us: ?u32 = null,
    ecn: ?u32 = null,
    ce_threshold_us: ?u32 = null,
    memory_limit: ?u32 = null,
    drop_batch: ?u32 = null,
};

fn appendFqCodelOptions(
    f: FqCodel,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) EncodeError!void {
    // Emission order mirrors iproute2's q_fq_codel.c so a request is
    // byte-identical to the equivalent `tc` command line.
    if (f.limit) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.LIMIT, v);
    if (f.flows) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.FLOWS, v);
    if (f.quantum) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.QUANTUM, v);
    if (f.interval_us) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.INTERVAL, v);
    if (f.target_us) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.TARGET, v);
    if (f.ecn) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.ECN, @intFromBool(v));
    if (f.ce_threshold_us) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.CE_THRESHOLD, v);
    if (f.memory_limit) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.MEMORY_LIMIT, v);
    if (f.drop_batch) |v| try codec.appendAttrU32(gpa, list, TCA_FQ_CODEL.DROP_BATCH_SIZE, v);
}

pub fn parseFqCodelOptions(data: []const u8) codec.Error!FqCodelWire {
    var fw: FqCodelWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| {
        if (a.data.len != 4) continue;
        const v = std.mem.readInt(u32, a.data[0..4], native_endian);
        switch (a.type) {
            TCA_FQ_CODEL.LIMIT => fw.limit = v,
            TCA_FQ_CODEL.FLOWS => fw.flows = v,
            TCA_FQ_CODEL.QUANTUM => fw.quantum = v,
            TCA_FQ_CODEL.INTERVAL => fw.interval_us = v,
            TCA_FQ_CODEL.TARGET => fw.target_us = v,
            TCA_FQ_CODEL.ECN => fw.ecn = v,
            TCA_FQ_CODEL.CE_THRESHOLD => fw.ce_threshold_us = v,
            TCA_FQ_CODEL.MEMORY_LIMIT => fw.memory_limit = v,
            TCA_FQ_CODEL.DROP_BATCH_SIZE => fw.drop_batch = v,
            else => {},
        }
    }
    return fw;
}

// ── mq ──────────────────────────────────────────────────────────────────────

/// The multiqueue root qdisc (`sch_mq`). It is a pure pivot: attaching it to a
/// multiqueue device makes the kernel auto-create one child class per hardware
/// TX queue (`1:1`, `1:2`, …), onto which per-CPU qdisc trees are hung. The
/// request carries **no `TCA_OPTIONS` at all** — not even an empty nest — which
/// is why `QdiscSpec.carriesOptions` returns false for it; the per-queue child
/// classes are created by the kernel, never by this call.
pub const Mq = struct {};

// ── cake ────────────────────────────────────────────────────────────────────

/// `TCA_CAKE_DIFFSERV_MODE` values (kernel `sch_cake.c` `CAKE_DIFFSERV_*`).
/// Non-exhaustive so a value a newer kernel adds still decodes.
pub const CakeDiffservMode = enum(u32) {
    diffserv3 = 0,
    diffserv4 = 1,
    diffserv8 = 2,
    besteffort = 3,
    precedence = 4,
    _,
};

/// `TCA_CAKE_FLOW_MODE` values (`CAKE_FLOW_*`). The dual/triple modes are bit
/// unions of the host/flow bits, exactly as the kernel names them.
pub const CakeFlowMode = enum(u32) {
    flowblind = 0,
    srchost = 1,
    dsthost = 2,
    hosts = 3,
    flows = 4,
    dual_srchost = 5,
    dual_dsthost = 6,
    triple_isolate = 7,
    _,
};

/// `TCA_CAKE_ATM` link-layer compensation values (`CAKE_ATM_*`).
pub const CakeAtmMode = enum(u32) {
    noatm = 0,
    atm = 1,
    ptm = 2,
    _,
};

/// `TCA_CAKE_ACK_FILTER` values (`CAKE_ACK_*`).
pub const CakeAckFilter = enum(u32) {
    none = 0,
    filter = 1,
    aggressive = 2,
    _,
};

/// A CAKE AQM/shaper qdisc (`sch_cake`, the LibreQoS per-subscriber leaf).
/// Every field is optional: `null` omits its attribute and keeps the kernel
/// default, exactly like leaving the argument off a `tc … cake` command line.
///
/// A few of `tc`'s command-line words expand to more than one attribute, and
/// this struct exposes each attribute directly so a request stays byte-exact:
///   * `bandwidth R` / `unlimited` set `bandwidth` **and** `autorate_ingress`
///     (to 0). `unlimited` is `bandwidth = 0`; a plain `bandwidth = null`
///     omits the attribute entirely (also unlimited, but no byte on the wire).
///   * `rtt T` sets `rtt_us` **and** `target_us` (to `rtt/20`).
///   * `raw` sets `atm = .noatm`, `overhead = 0` **and** `raw = true`.
/// See SPEC.md for the emission order and the `raw` position caveat.
pub const Cake = struct {
    /// `bandwidth`/`unlimited` shaper rate in **bytes per second**
    /// (`TCA_CAKE_BASE_RATE64`, u64). null omits it (kernel-default unlimited);
    /// 0 emits an explicit unlimited like `tc … cake unlimited`.
    bandwidth: ?u64 = null,
    /// DiffServ tin mapping (`diffserv3`/`diffserv4`/…, `TCA_CAKE_DIFFSERV_MODE`).
    diffserv: ?CakeDiffservMode = null,
    /// Link-layer ATM/PTM compensation (`atm`/`ptm`/`noatm`, `TCA_CAKE_ATM`).
    atm: ?CakeAtmMode = null,
    /// Flow-isolation mode (`srchost`/`hosts`/`triple-isolate`/…,
    /// `TCA_CAKE_FLOW_MODE`).
    flow_mode: ?CakeFlowMode = null,
    /// Per-packet overhead in bytes (`overhead`, `TCA_CAKE_OVERHEAD`); signed,
    /// `tc` accepts −64..256.
    overhead: ?i32 = null,
    /// `raw` — disable the overhead/ATM keep-the-kernel-honest compensation
    /// (`TCA_CAKE_RAW`, a presence flag carrying 0).
    raw: bool = false,
    /// Minimum packet size in bytes (`mpu`, `TCA_CAKE_MPU`).
    mpu: ?u32 = null,
    /// AQM interval in microseconds (`rtt`, `TCA_CAKE_RTT`).
    rtt_us: ?u32 = null,
    /// AQM target in microseconds (`TCA_CAKE_TARGET`); `tc`'s `rtt` keyword
    /// sets this to `rtt/20`.
    target_us: ?u32 = null,
    /// `autorate-ingress` bandwidth estimation (`TCA_CAKE_AUTORATE`, 0/1).
    autorate_ingress: ?bool = null,
    /// Queue-memory budget in bytes (`memlimit`, `TCA_CAKE_MEMORY`).
    memlimit: ?u32 = null,
    /// Firewall-mark mask for tin selection (`fwmark`, `TCA_CAKE_FWMARK`).
    fwmark: ?u32 = null,
    /// De-NAT host isolation (`nat`/`nonat`, `TCA_CAKE_NAT`, 0/1).
    nat: ?bool = null,
    /// Clear DSCP after classifying (`wash`/`nowash`, `TCA_CAKE_WASH`, 0/1).
    wash: ?bool = null,
    /// Coalesce super-packets before shaping (`split-gso`/`no-split-gso`,
    /// `TCA_CAKE_SPLIT_GSO`, 0/1).
    split_gso: ?bool = null,
    /// ACK-thinning mode (`ack-filter`/`ack-filter-aggressive`/`no-ack-filter`,
    /// `TCA_CAKE_ACK_FILTER`).
    ack_filter: ?CakeAckFilter = null,
    /// Shape at ingress instead of egress (`ingress`, `TCA_CAKE_INGRESS`, 0/1).
    ingress: ?bool = null,
};

/// Wire readback of a cake qdisc's options — the raw kernel values, one
/// optional per attribute (mirroring `FqCodelWire`).
pub const CakeWire = struct {
    bandwidth: ?u64 = null,
    diffserv: ?u32 = null,
    atm: ?u32 = null,
    flow_mode: ?u32 = null,
    overhead: ?i32 = null,
    raw: bool = false,
    mpu: ?u32 = null,
    rtt_us: ?u32 = null,
    target_us: ?u32 = null,
    autorate_ingress: ?u32 = null,
    memlimit: ?u32 = null,
    fwmark: ?u32 = null,
    nat: ?u32 = null,
    wash: ?u32 = null,
    split_gso: ?u32 = null,
    ack_filter: ?u32 = null,
    ingress: ?u32 = null,
};

fn appendCakeOptions(
    c: Cake,
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
) EncodeError!void {
    // Emission order mirrors iproute2's q_cake.c so a request is byte-identical
    // to the equivalent `tc` command line (verified against captured goldens).
    if (c.bandwidth) |v| try appendAttrU64(gpa, list, TCA_CAKE.BASE_RATE64, v);
    if (c.diffserv) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.DIFFSERV_MODE, @intFromEnum(v));
    if (c.atm) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.ATM, @intFromEnum(v));
    if (c.flow_mode) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.FLOW_MODE, @intFromEnum(v));
    if (c.overhead) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.OVERHEAD, @bitCast(v));
    if (c.raw) try codec.appendAttrU32(gpa, list, TCA_CAKE.RAW, 0);
    if (c.mpu) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.MPU, v);
    if (c.rtt_us) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.RTT, v);
    if (c.target_us) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.TARGET, v);
    if (c.autorate_ingress) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.AUTORATE, @intFromBool(v));
    if (c.memlimit) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.MEMORY, v);
    if (c.fwmark) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.FWMARK, v);
    if (c.nat) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.NAT, @intFromBool(v));
    if (c.wash) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.WASH, @intFromBool(v));
    if (c.split_gso) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.SPLIT_GSO, @intFromBool(v));
    if (c.ack_filter) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.ACK_FILTER, @intFromEnum(v));
    if (c.ingress) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.INGRESS, @intFromBool(v));
}

/// Parse a `TCA_OPTIONS` payload for a cake qdisc: a flat list of `TCA_CAKE_*`
/// TLVs. Attributes with an unexpected length are ignored rather than
/// rejected, exactly like the other option parsers.
pub fn parseCakeOptions(data: []const u8) codec.Error!CakeWire {
    var cw: CakeWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_CAKE.BASE_RATE64 => if (a.data.len == 8) {
            cw.bandwidth = std.mem.readInt(u64, a.data[0..8], native_endian);
        },
        TCA_CAKE.RAW => cw.raw = true,
        TCA_CAKE.OVERHEAD => if (a.data.len == 4) {
            cw.overhead = @bitCast(std.mem.readInt(u32, a.data[0..4], native_endian));
        },
        else => if (a.data.len == 4) {
            const v = std.mem.readInt(u32, a.data[0..4], native_endian);
            switch (a.type) {
                TCA_CAKE.DIFFSERV_MODE => cw.diffserv = v,
                TCA_CAKE.ATM => cw.atm = v,
                TCA_CAKE.FLOW_MODE => cw.flow_mode = v,
                TCA_CAKE.MPU => cw.mpu = v,
                TCA_CAKE.RTT => cw.rtt_us = v,
                TCA_CAKE.TARGET => cw.target_us = v,
                TCA_CAKE.AUTORATE => cw.autorate_ingress = v,
                TCA_CAKE.MEMORY => cw.memlimit = v,
                TCA_CAKE.FWMARK => cw.fwmark = v,
                TCA_CAKE.NAT => cw.nat = v,
                TCA_CAKE.WASH => cw.wash = v,
                TCA_CAKE.SPLIT_GSO => cw.split_gso = v,
                TCA_CAKE.ACK_FILTER => cw.ack_filter = v,
                TCA_CAKE.INGRESS => cw.ingress = v,
                else => {},
            }
        },
    };
    return cw;
}

// ── the spec unions ─────────────────────────────────────────────────────────

/// Escape hatch for a kind this module does not model: a `TCA_KIND` string
/// plus an already-encoded `TCA_OPTIONS` payload (borrowed, not copied).
pub const Raw = struct {
    kind: []const u8,
    options: []const u8 = &.{},
};

/// What to attach as a **qdisc**.
pub const QdiscSpec = union(enum) {
    netem: Netem,
    htb: Htb,
    tbf: Tbf,
    fq_codel: FqCodel,
    mq: Mq,
    cake: Cake,
    raw: Raw,

    pub fn kind(self: QdiscSpec) []const u8 {
        return switch (self) {
            .netem => kind_netem,
            .htb => kind_htb,
            .tbf => kind_tbf,
            .fq_codel => kind_fq_codel,
            .mq => kind_mq,
            .cake => kind_cake,
            .raw => |r| r.kind,
        };
    }

    /// Whether this kind puts a `TCA_OPTIONS` attribute on the wire at all.
    /// `mq` sends **none** — not even an empty nest — because the kernel
    /// auto-populates its per-queue children; a byte-exact request must omit
    /// the attribute entirely. Every other kind carries an options nest (empty
    /// when no knobs are set, exactly like `tc`).
    pub fn carriesOptions(self: QdiscSpec) bool {
        return switch (self) {
            .mq => false,
            else => true,
        };
    }

    /// Append this spec's `TCA_OPTIONS` **payload** (the caller owns the
    /// surrounding nest). Never called for a kind whose `carriesOptions` is
    /// false.
    pub fn appendOptions(
        self: QdiscSpec,
        gpa: std.mem.Allocator,
        list: *std.ArrayList(u8),
        ps: Psched,
    ) EncodeError!void {
        switch (self) {
            .netem => |n| try appendNetemOptions(n, gpa, list),
            .htb => |h| try appendHtbOptions(h, gpa, list),
            .tbf => |t| try appendTbfOptions(t, gpa, list, ps),
            .fq_codel => |f| try appendFqCodelOptions(f, gpa, list),
            .mq => {}, // no options; carriesOptions() gates the nest away
            .cake => |c| try appendCakeOptions(c, gpa, list),
            .raw => |r| {
                if (r.options.len > std.math.maxInt(u16)) return error.OptionsTooLong;
                try list.appendSlice(gpa, r.options);
                try list.appendNTimes(gpa, 0, codec.alignUp(r.options.len) - r.options.len);
            },
        }
    }
};

/// What to attach as a **class** (`RTM_NEWTCLASS`).
pub const ClassSpec = union(enum) {
    htb: HtbClass,
    raw: Raw,

    pub fn kind(self: ClassSpec) []const u8 {
        return switch (self) {
            .htb => kind_htb,
            .raw => |r| r.kind,
        };
    }

    pub fn appendOptions(
        self: ClassSpec,
        gpa: std.mem.Allocator,
        list: *std.ArrayList(u8),
        ps: Psched,
    ) EncodeError!void {
        switch (self) {
            .htb => |c| try appendHtbClassOptions(c, gpa, list, ps),
            .raw => |r| {
                if (r.options.len > std.math.maxInt(u16)) return error.OptionsTooLong;
                try list.appendSlice(gpa, r.options);
                try list.appendNTimes(gpa, 0, codec.alignUp(r.options.len) - r.options.len);
            },
        }
    }
};

// ── parsed dump entries ─────────────────────────────────────────────────────

/// Longest `TCA_KIND` this module stores verbatim (`IFNAMSIZ`-ish; the
/// longest real qdisc name is "pfifo_head_drop" at 15).
pub const kind_max = 16;

/// One qdisc, as read back by an `RTM_GETQDISC` dump. At most one of the
/// option fields is non-null — whichever matches `kind()`; a kind this module
/// does not model still reports its ifindex/handle/parent/kind.
pub const Qdisc = struct {
    ifindex: u32,
    handle: Handle,
    parent: Handle,
    kind_buf: [kind_max]u8 = @splat(0),
    kind_len: u8 = 0,
    netem: ?NetemWire = null,
    htb: ?HtbWire = null,
    tbf: ?TbfWire = null,
    fq_codel: ?FqCodelWire = null,
    cake: ?CakeWire = null,

    /// The qdisc kind string ("netem", "noqueue", "fq_codel", …).
    pub fn kind(q: *const Qdisc) []const u8 {
        return q.kind_buf[0..q.kind_len];
    }
};

/// One class, as read back by an `RTM_GETTCLASS` dump.
pub const Class = struct {
    ifindex: u32,
    handle: Handle,
    parent: Handle,
    kind_buf: [kind_max]u8 = @splat(0),
    kind_len: u8 = 0,
    htb: ?HtbClassWire = null,

    pub fn kind(c: *const Class) []const u8 {
        return c.kind_buf[0..c.kind_len];
    }
};

/// `sizeof(struct tcmsg)`: u8 family, u8 pad1, u16 pad2, i32 ifindex,
/// u32 handle, u32 parent, u32 info.
pub const tcmsg_len = 20;

fn copyKind(buf: *[kind_max]u8, len: *u8, s: []const u8) codec.Error!void {
    if (s.len > kind_max) return error.BadLength;
    @memcpy(buf[0..s.len], s);
    len.* = @intCast(s.len);
}

/// Parse an `RTM_NEWQDISC` payload (`struct tcmsg` + `TCA_*`) into a `Qdisc`.
pub fn parseQdisc(payload: []const u8) codec.Error!Qdisc {
    if (payload.len < tcmsg_len) return error.Truncated;
    var q: Qdisc = .{
        .ifindex = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian)),
        .handle = Handle.fromRaw(std.mem.readInt(u32, payload[8..12], native_endian)),
        .parent = Handle.fromRaw(std.mem.readInt(u32, payload[12..16], native_endian)),
    };
    var options_data: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = payload[tcmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        TCA.KIND => try copyKind(&q.kind_buf, &q.kind_len, a.asString()),
        TCA.OPTIONS => options_data = a.data,
        else => {},
    };
    if (options_data) |opt| {
        const k = q.kind();
        if (std.mem.eql(u8, k, kind_netem)) {
            q.netem = try parseNetemOptions(opt);
        } else if (std.mem.eql(u8, k, kind_htb)) {
            q.htb = try parseHtbOptions(opt);
        } else if (std.mem.eql(u8, k, kind_tbf)) {
            q.tbf = try parseTbfOptions(opt);
        } else if (std.mem.eql(u8, k, kind_fq_codel)) {
            q.fq_codel = try parseFqCodelOptions(opt);
        } else if (std.mem.eql(u8, k, kind_cake)) {
            q.cake = try parseCakeOptions(opt);
        }
    }
    return q;
}

/// Parse an `RTM_NEWTCLASS` payload into a `Class`.
pub fn parseClass(payload: []const u8) codec.Error!Class {
    if (payload.len < tcmsg_len) return error.Truncated;
    var c: Class = .{
        .ifindex = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian)),
        .handle = Handle.fromRaw(std.mem.readInt(u32, payload[8..12], native_endian)),
        .parent = Handle.fromRaw(std.mem.readInt(u32, payload[12..16], native_endian)),
    };
    var options_data: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = payload[tcmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        TCA.KIND => try copyKind(&c.kind_buf, &c.kind_len, a.asString()),
        TCA.OPTIONS => options_data = a.data,
        else => {},
    };
    if (options_data) |opt| {
        if (std.mem.eql(u8, c.kind(), kind_htb)) {
            c.htb = try parseHtbClassOptions(opt);
        }
    }
    return c;
}

// ── small local helpers ─────────────────────────────────────────────────────

/// `codec.appendAttr` with the `AttrTooLong` case folded away: every payload
/// this module builds is a fixed struct or a 1 KiB rate table.
fn appendAttr(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) std.mem.Allocator.Error!void {
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // <= 1024 bytes by construction
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// DRY candidate: `netlink.codec` has `appendAttrU32` but no u64 counterpart
/// (nothing in `netlink` needs one yet). Drop this once it grows one.
fn appendAttrU64(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    value: u64,
) std.mem.Allocator.Error!void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, value, native_endian);
    try appendAttr(gpa, list, attr_type, &raw);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "attribute-type constants agree with the kernel UAPI" {
    try testing.expectEqual(@as(u16, 1), TCA.KIND);
    try testing.expectEqual(@as(u16, 2), TCA.OPTIONS);
    try testing.expectEqual(@as(u16, 1), TCA_NETEM.CORR);
    try testing.expectEqual(@as(u16, 10), TCA_NETEM.LATENCY64);
    try testing.expectEqual(@as(u16, 1), TCA_HTB.PARMS);
    try testing.expectEqual(@as(u16, 2), TCA_HTB.INIT);
    try testing.expectEqual(@as(u16, 3), TCA_HTB.CTAB);
    try testing.expectEqual(@as(u16, 4), TCA_HTB.RTAB);
    try testing.expectEqual(@as(u16, 6), TCA_HTB.RATE64);
    try testing.expectEqual(@as(u16, 7), TCA_HTB.CEIL64);
    try testing.expectEqual(@as(u16, 1), TCA_TBF.PARMS);
    try testing.expectEqual(@as(u16, 6), TCA_TBF.BURST);
    try testing.expectEqual(@as(u16, 2), TCA_FQ_CODEL.LIMIT);
    try testing.expectEqual(@as(u16, 6), TCA_FQ_CODEL.QUANTUM);
    try testing.expectEqual(@as(u16, 2), TCA_CAKE.BASE_RATE64);
    try testing.expectEqual(@as(u16, 6), TCA_CAKE.OVERHEAD);
    try testing.expectEqual(@as(u16, 14), TCA_CAKE.MPU);
    try testing.expectEqual(@as(u16, 16), TCA_CAKE.ACK_FILTER);
    try testing.expectEqual(@as(u16, 18), TCA_CAKE.FWMARK);
    // cake enum values match the kernel's sch_cake.c constants.
    try testing.expectEqual(@as(u32, 1), @intFromEnum(CakeDiffservMode.diffserv4));
    try testing.expectEqual(@as(u32, 5), @intFromEnum(CakeFlowMode.dual_srchost));
    try testing.expectEqual(@as(u32, 2), @intFromEnum(CakeAtmMode.ptm));
    try testing.expectEqual(@as(u32, 1), @intFromEnum(CakeAckFilter.filter));
    try testing.expectEqual(@as(usize, 20), tcmsg_len);
    try testing.expectEqual(@as(usize, 44), tc_htb_opt_len);
    try testing.expectEqual(@as(usize, 36), tc_tbf_qopt_len);
}

test "percentToU32: range + rounding" {
    try testing.expectEqual(@as(u32, 0), try percentToU32(0));
    try testing.expectEqual(std.math.maxInt(u32), try percentToU32(100));
    try testing.expectEqual(@as(u32, 42949673), try percentToU32(1.0));
    try testing.expectEqual(@as(u32, 2147483648), try percentToU32(50.0));
    try testing.expectError(error.InvalidPercent, percentToU32(-0.1));
    try testing.expectError(error.InvalidPercent, percentToU32(100.1));
    try testing.expectError(error.InvalidPercent, percentToU32(std.math.nan(f64)));
}

test "clampRate pins >= 2^32 rates to ~0U" {
    try testing.expectEqual(@as(u32, 125_000), clampRate(125_000));
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), clampRate(0xFFFFFFFF));
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), clampRate(1 << 32));
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), clampRate(5_000_000_000));
}

test "encode/decode round-trip: htb class options" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const spec: HtbClass = .{
        .rate = 5_000_000_000, // needs RATE64
        .ceil = 10_000_000_000, // needs CEIL64
        .prio = 3,
        .quantum = 3000,
    };
    try appendHtbClassOptions(spec, gpa, &list, ratespec.golden_psched);
    const cw = try parseHtbClassOptions(list.items);
    try testing.expectEqual(@as(u64, 5_000_000_000), cw.rate64);
    try testing.expectEqual(@as(u64, 10_000_000_000), cw.ceil64);
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), cw.rate.rate); // clamped
    try testing.expectEqual(@as(u32, 3), cw.prio);
    try testing.expectEqual(@as(u32, 3000), cw.quantum);
    try testing.expectEqual(@as(u8, 3), cw.rate.cell_log);
    try testing.expectEqual(@as(i16, -1), cw.rate.cell_align);
}

test "encode/decode round-trip: tbf options with a peak bucket" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const spec: Tbf = .{
        .rate = 1_250_000,
        .burst = 10240,
        .latency_us = 50_000,
        .peakrate = 2_500_000,
        .mtu = 1540,
    };
    try appendTbfOptions(spec, gpa, &list, ratespec.golden_psched);
    const tw = try parseTbfOptions(list.items);
    try testing.expectEqual(@as(u32, 1_250_000), tw.rate.rate);
    try testing.expectEqual(@as(u32, 2_500_000), tw.peakrate.rate);
    try testing.expectEqual(@as(u32, 72_740), tw.limit);
    try testing.expectEqual(@as(?u32, 10240), tw.burst_bytes);
    try testing.expectEqual(@as(?u32, 1540), tw.pburst_bytes);
}

test "encode/decode round-trip: fq_codel omits unset fields" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendFqCodelOptions(.{ .limit = 1200, .target_us = 5000 }, gpa, &list);
    try testing.expectEqual(@as(usize, 16), list.items.len); // two u32 attrs
    const fw = try parseFqCodelOptions(list.items);
    try testing.expectEqual(@as(?u32, 1200), fw.limit);
    try testing.expectEqual(@as(?u32, 5000), fw.target_us);
    try testing.expectEqual(@as(?u32, null), fw.flows);
    try testing.expectEqual(@as(?u32, null), fw.quantum);
}

test "encode/decode round-trip: cake omits unset fields" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendCakeOptions(.{
        .bandwidth = 12_500_000, // 100 Mbit/s in bytes/s
        .diffserv = .diffserv4,
        .flow_mode = .dual_srchost,
        .overhead = -18,
        .mpu = 64,
        .ack_filter = .aggressive,
    }, gpa, &list);
    const cw = try parseCakeOptions(list.items);
    try testing.expectEqual(@as(?u64, 12_500_000), cw.bandwidth);
    try testing.expectEqual(@as(?u32, 1), cw.diffserv);
    try testing.expectEqual(@as(?u32, 5), cw.flow_mode);
    try testing.expectEqual(@as(?i32, -18), cw.overhead); // signed round-trip
    try testing.expectEqual(@as(?u32, 64), cw.mpu);
    try testing.expectEqual(@as(?u32, 2), cw.ack_filter);
    // Everything left unset stays absent, and no RAW attribute was emitted.
    try testing.expectEqual(false, cw.raw);
    try testing.expectEqual(@as(?u32, null), cw.rtt_us);
    try testing.expectEqual(@as(?u32, null), cw.fwmark);
    try testing.expectEqual(@as(?u32, null), cw.ingress);
}

test "cake: unlimited bandwidth and the raw flag" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // Explicit unlimited emits BASE_RATE64 = 0 (like `tc … cake unlimited`),
    // and `raw` emits a bare presence attribute the parser flags true.
    try appendCakeOptions(.{ .bandwidth = 0, .raw = true }, gpa, &list);
    const cw = try parseCakeOptions(list.items);
    try testing.expectEqual(@as(?u64, 0), cw.bandwidth);
    try testing.expectEqual(true, cw.raw);

    // A wholly-default cake emits nothing at all.
    list.clearRetainingCapacity();
    try appendCakeOptions(.{}, gpa, &list);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "spec validation rejects unbuildable qdiscs before allocating" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const ps = ratespec.golden_psched;
    try testing.expectError(error.MissingRate, appendTbfOptions(.{ .rate = 0, .burst = 1 }, gpa, &list, ps));
    try testing.expectError(error.MissingBurst, appendTbfOptions(.{ .rate = 1, .burst = 0 }, gpa, &list, ps));
    try testing.expectError(error.MissingLimit, appendTbfOptions(.{ .rate = 1, .burst = 1 }, gpa, &list, ps));
    try testing.expectError(error.MissingMtu, appendTbfOptions(
        .{ .rate = 1, .burst = 1, .limit = 1, .peakrate = 2 },
        gpa,
        &list,
        ps,
    ));
    try testing.expectError(error.MissingRate, appendHtbClassOptions(.{ .rate = 0 }, gpa, &list, ps));
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "QdiscSpec.kind covers every modelled kind" {
    try testing.expectEqualStrings("netem", (QdiscSpec{ .netem = .{} }).kind());
    try testing.expectEqualStrings("htb", (QdiscSpec{ .htb = .{} }).kind());
    try testing.expectEqualStrings("tbf", (QdiscSpec{ .tbf = .{ .rate = 1, .burst = 1, .limit = 1 } }).kind());
    try testing.expectEqualStrings("fq_codel", (QdiscSpec{ .fq_codel = .{} }).kind());
    try testing.expectEqualStrings("mq", (QdiscSpec{ .mq = .{} }).kind());
    try testing.expectEqualStrings("cake", (QdiscSpec{ .cake = .{} }).kind());
    try testing.expectEqualStrings("sfq", (QdiscSpec{ .raw = .{ .kind = "sfq" } }).kind());
    try testing.expectEqualStrings("htb", (ClassSpec{ .htb = .{ .rate = 1 } }).kind());
    // Only mq withholds the options nest.
    try testing.expect(!(QdiscSpec{ .mq = .{} }).carriesOptions());
    try testing.expect((QdiscSpec{ .cake = .{} }).carriesOptions());
    try testing.expect((QdiscSpec{ .fq_codel = .{} }).carriesOptions());
}

test "fuzz: option parsers never crash on arbitrary payloads" {
    try testing.fuzz({}, fuzzParseOptions, .{});
}

fn fuzzParseOptions(_: void, smith: *std.testing.Smith) !void {
    var raw: [256]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const buf = raw[0..len];
    if (parseNetemOptions(buf)) |_| {} else |_| {}
    if (parseHtbOptions(buf)) |_| {} else |_| {}
    if (parseHtbClassOptions(buf)) |_| {} else |_| {}
    if (parseTbfOptions(buf)) |_| {} else |_| {}
    if (parseFqCodelOptions(buf)) |_| {} else |_| {}
    if (parseCakeOptions(buf)) |_| {} else |_| {}
    if (parseQdisc(buf)) |_| {} else |_| {}
    if (parseClass(buf)) |_| {} else |_| {}
}
