// SPDX-License-Identifier: MIT
//! Qdisc and class option encoding/decoding: the kind-specific `TCA_OPTIONS`
//! payloads for **netem**, **htb**, **tbf**, **fq_codel**, **cake**, **prio**,
//! **pfifo**/**bfifo**, **sfq**, **codel** and **fq**.
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

// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

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

/// Generic statistics attribute types (linux/gen_stats.h `TCA_STATS_*`),
/// nested inside `TCA_STATS2`.
pub const TCA_STATS2 = struct {
    pub const UNSPEC: u16 = 0;
    pub const BASIC: u16 = 1;
    pub const RATE_EST: u16 = 2;
    pub const QUEUE: u16 = 3;
    pub const APP: u16 = 4;
    pub const RATE_EST64: u16 = 5;
    pub const PAD: u16 = 6;
    pub const BASIC_HW: u16 = 7;
    pub const PKT64: u16 = 8;
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
    pub const SLOT: u16 = 12;
    pub const SLOT_DIST: u16 = 13;
    pub const PRNG_SEED: u16 = 14;
};

/// `NETEM_LOSS_*` — the models nested in `TCA_NETEM_LOSS`.
pub const NETEM_LOSS = struct {
    pub const GI: u16 = 1;
    pub const GE: u16 = 2;
};

/// `sizeof(struct tc_netem_slot)`.
pub const tc_netem_slot_len = 40;
/// The longest distribution table netem takes (`MAX_DIST` in the kernel is
/// 16384 entries; one netlink attribute is the tighter bound here).
pub const netem_max_dist = (std.math.maxInt(u16) - 4) / 2;

/// `loss gemodel PERCENT [R [1-H [1-K]]]` — the Gilbert-Elliott model, the
/// four arguments in percent, named as the command line has them. `tc` sends
/// `p`, `r` and `k1 = 1-K` as given and `h` as `UINT32_MAX - scale(1-H)`.
pub const NetemGe = struct {
    p_pct: f64,
    r_pct: f64 = 0,
    one_minus_h_pct: f64 = 0,
    one_minus_k_pct: f64 = 0,
};

/// `loss state` — the 4-state Markov model (`tc_netem_gimodel`), transition
/// probabilities in percent.
pub const NetemGi = struct {
    p13_pct: f64,
    p31_pct: f64 = 0,
    p32_pct: f64 = 0,
    p14_pct: f64 = 0,
    p23_pct: f64 = 0,
};

/// A netem packet-loss model beyond plain random loss.
pub const NetemLoss = union(enum) {
    gemodel: NetemGe,
    state: NetemGi,
};

/// `struct tc_netem_slot` — `slot MIN [MAX] [packets N] [bytes N]`, or the
/// distribution form `slot distribution DIST DELAY JITTER`: delivery in
/// bursts at slot boundaries.
pub const NetemSlot = struct {
    min_delay_ns: i64 = 0,
    max_delay_ns: i64 = 0,
    max_packets: i32 = 0,
    max_bytes: i32 = 0,
    dist_delay_ns: i64 = 0,
    dist_jitter_ns: i64 = 0,
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

/// codel attribute types (linux/pkt_sched.h `TCA_CODEL_*`).
/// `TCA_RED_*` (`pkt_sched.h`).
pub const TCA_RED = struct {
    pub const UNSPEC: u16 = 0;
    pub const PARMS: u16 = 1;
    pub const STAB: u16 = 2;
    pub const MAX_P: u16 = 3;
    pub const FLAGS: u16 = 4;
};

pub const TCA_CODEL = struct {
    pub const UNSPEC: u16 = 0;
    pub const TARGET: u16 = 1;
    pub const LIMIT: u16 = 2;
    pub const INTERVAL: u16 = 3;
    pub const ECN: u16 = 4;
    pub const CE_THRESHOLD: u16 = 5;
};

/// fq attribute types (linux/pkt_sched.h `TCA_FQ_*`).
pub const TCA_FQ = struct {
    pub const UNSPEC: u16 = 0;
    pub const PLIMIT: u16 = 1;
    pub const FLOW_PLIMIT: u16 = 2;
    pub const QUANTUM: u16 = 3;
    pub const INITIAL_QUANTUM: u16 = 4;
    pub const RATE_ENABLE: u16 = 5;
    pub const FLOW_DEFAULT_RATE: u16 = 6;
    pub const FLOW_MAX_RATE: u16 = 7;
    pub const BUCKETS_LOG: u16 = 8;
    pub const FLOW_REFILL_DELAY: u16 = 9;
    pub const ORPHAN_MASK: u16 = 10;
    pub const LOW_RATE_THRESHOLD: u16 = 11;
    pub const CE_THRESHOLD: u16 = 12;
    pub const TIMER_SLACK: u16 = 13;
    pub const HORIZON: u16 = 14;
    pub const HORIZON_DROP: u16 = 15;
    pub const PRIO: u16 = 16;
    pub const WEIGHTS: u16 = 17;
    pub const OFFLOAD_HORIZON: u16 = 18;
};

/// prio's nested attribute (`TCA_PRIO_MQ`).
pub const TCA_PRIO_MQ: u16 = 1;

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
pub const kind_ingress = "ingress";
pub const kind_clsact = "clsact";
pub const kind_cake = "cake";
pub const kind_prio = "prio";
pub const kind_pfifo = "pfifo";
pub const kind_bfifo = "bfifo";
pub const kind_sfq = "sfq";
pub const kind_codel = "codel";
pub const kind_fq = "fq";
pub const kind_hfsc = "hfsc";
pub const kind_red = "red";
pub const kind_pfifo_fast = "pfifo_fast";
pub const kind_pfifo_head_drop = "pfifo_head_drop";

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
    /// `cell_log`/`ccell_log` outside `[0, ratespec.max_cell_log]` — see
    /// `ratespec.checkCellLog`.
    InvalidCellLog,
    /// A `prio` qdisc with `bands` outside `[2, 16]` or a priomap entry `>= bands`.
    InvalidPrioBands,
    /// A size table (`stab`) with a zero `mtu` or `tsize`, or a `tsize` whose
    /// table does not fit one netlink attribute.
    InvalidStab,
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
    /// Rate limit in bytes/s ("rate Rbit/Rbps"). 0 = unlimited. A rate past
    /// `u32` is carried in `TCA_NETEM_RATE64` (the `u32` field pinned to
    /// `~0U`, as `tc` sends it).
    rate_bytes_per_sec: u64 = 0,
    /// `rate R PACKETOVERHEAD CELLSIZE CELLOVERHEAD`.
    packet_overhead: i32 = 0,
    cell_size: u32 = 0,
    cell_overhead: i32 = 0,
    /// `ecn` — mark instead of dropping (`TCA_NETEM_ECN`).
    ecn: bool = false,
    /// `loss gemodel …` / `loss state …` (`TCA_NETEM_LOSS`); replaces
    /// `loss_pct`'s random loss for the kernel.
    loss_model: ?NetemLoss = null,
    /// A delay distribution table (`delay … distribution NAME`; `tc` reads
    /// the 4096-entry tables of its `.dist` files). Signed 16-bit entries,
    /// `TCA_NETEM_DELAY_DIST`. This module ships none.
    delay_dist: []const i16 = &.{},
    slot: ?NetemSlot = null,
    /// The table of `slot distribution` (`TCA_NETEM_SLOT_DIST`).
    slot_dist: []const i16 = &.{},
    /// `seed N` — the random generator's seed (`TCA_NETEM_PRNG_SEED`).
    prng_seed: ?u64 = null,
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
    /// `TCA_NETEM_RATE.rate` (bytes/s); 0 if absent. `~0U` when `rate64`
    /// carries the real value.
    rate_bytes_per_sec: u32 = 0,
    packet_overhead: i32 = 0,
    cell_size: u32 = 0,
    cell_overhead: i32 = 0,
    /// `TCA_NETEM_RATE64`, bytes/s; 0 if absent.
    rate64: u64 = 0,
    ecn: bool = false,
    /// The raw `tc_netem_gimodel` (`p13`, `p31`, `p32`, `p14`, `p23`).
    loss_gi: ?[5]u32 = null,
    /// The raw `tc_netem_gemodel` (`p`, `r`, `h`, `k1`).
    loss_ge: ?[4]u32 = null,
    /// How many entries the delay / slot distribution tables carried.
    delay_dist_len: u16 = 0,
    slot_dist_len: u16 = 0,
    slot: ?NetemSlot = null,
    prng_seed: ?u64 = null,
};

/// Scale a `[0, 100]` percent to the kernel's `u32` probability scale
/// (`percent/100 * UINT32_MAX`, rounded half to even — matches `tc`'s own
/// scaling).
pub fn percentToU32(pct: f64) error{InvalidPercent}!u32 {
    if (!(pct >= 0.0 and pct <= 100.0)) return error.InvalidPercent;
    const x = pct / 100.0 * @as(f64, @floatFromInt(std.math.maxInt(u32)));
    // Round half to even, as `tc` does (`rint`): 70% lands exactly on a half
    // (3006477106.5) and `tc` sends ...106, where round-half-away gave ...107.
    const f = @floor(x);
    const d = x - f;
    const up = d > 0.5 or (d == 0.5 and @mod(f, 2.0) != 0.0);
    return @intFromFloat(if (up) f + 1.0 else f);
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
    if (n.ecn) try codec.appendAttrU32(gpa, list, TCA_NETEM.ECN, 1);
    if (n.loss_model) |m| try appendLossModel(gpa, list, m);
    if (n.rate_bytes_per_sec != 0 or n.packet_overhead != 0 or n.cell_size != 0 or n.cell_overhead != 0) {
        // struct tc_netem_rate: rate, packet_overhead, cell_size,
        // cell_overhead. A rate past 32 bits is pinned to ~0U with the real
        // value in RATE64, which `tc` sends first.
        var rate: [16]u8 = @splat(0);
        const clamped: u32 = if (n.rate_bytes_per_sec >= (1 << 32))
            std.math.maxInt(u32)
        else
            @intCast(n.rate_bytes_per_sec);
        std.mem.writeInt(u32, rate[0..4], clamped, native_endian);
        std.mem.writeInt(i32, rate[4..8], n.packet_overhead, native_endian);
        std.mem.writeInt(u32, rate[8..12], n.cell_size, native_endian);
        std.mem.writeInt(i32, rate[12..16], n.cell_overhead, native_endian);
        if (n.rate_bytes_per_sec >= (1 << 32)) try appendAttrU64(gpa, list, TCA_NETEM.RATE64, n.rate_bytes_per_sec);
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
    if (n.delay_dist.len != 0) try appendDistTable(gpa, list, TCA_NETEM.DELAY_DIST, n.delay_dist);
    if (n.slot) |sl| {
        var raw: [tc_netem_slot_len]u8 = undefined;
        std.mem.writeInt(i64, raw[0..8], sl.min_delay_ns, native_endian);
        std.mem.writeInt(i64, raw[8..16], sl.max_delay_ns, native_endian);
        std.mem.writeInt(i32, raw[16..20], sl.max_packets, native_endian);
        std.mem.writeInt(i32, raw[20..24], sl.max_bytes, native_endian);
        std.mem.writeInt(i64, raw[24..32], sl.dist_delay_ns, native_endian);
        std.mem.writeInt(i64, raw[32..40], sl.dist_jitter_ns, native_endian);
        try appendAttr(gpa, list, TCA_NETEM.SLOT, &raw);
    }
    if (n.slot_dist.len != 0) try appendDistTable(gpa, list, TCA_NETEM.SLOT_DIST, n.slot_dist);
    if (n.prng_seed) |seed| try appendAttrU64(gpa, list, TCA_NETEM.PRNG_SEED, seed);
}

fn appendDistTable(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    table: []const i16,
) EncodeError!void {
    if (table.len > netem_max_dist) return error.OptionsTooLong;
    const raw = try gpa.alloc(u8, table.len * 2);
    defer gpa.free(raw);
    for (table, 0..) |v, i| std.mem.writeInt(i16, raw[i * 2 ..][0..2], v, native_endian);
    try appendAttr(gpa, list, attr_type, raw);
}

fn appendLossModel(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    model: NetemLoss,
) EncodeError!void {
    const nest = try codec.nestBegin(gpa, list, TCA_NETEM.LOSS | codec.NLA_F_NESTED);
    switch (model) {
        .state => |g| {
            var raw: [20]u8 = undefined;
            std.mem.writeInt(u32, raw[0..4], try percentToU32(g.p13_pct), native_endian);
            std.mem.writeInt(u32, raw[4..8], try percentToU32(g.p31_pct), native_endian);
            std.mem.writeInt(u32, raw[8..12], try percentToU32(g.p32_pct), native_endian);
            std.mem.writeInt(u32, raw[12..16], try percentToU32(g.p14_pct), native_endian);
            std.mem.writeInt(u32, raw[16..20], try percentToU32(g.p23_pct), native_endian);
            try appendAttr(gpa, list, NETEM_LOSS.GI, &raw);
        },
        .gemodel => |g| {
            var raw: [16]u8 = undefined;
            std.mem.writeInt(u32, raw[0..4], try percentToU32(g.p_pct), native_endian);
            std.mem.writeInt(u32, raw[4..8], try percentToU32(g.r_pct), native_endian);
            std.mem.writeInt(u32, raw[8..12], std.math.maxInt(u32) - try percentToU32(g.one_minus_h_pct), native_endian);
            std.mem.writeInt(u32, raw[12..16], try percentToU32(g.one_minus_k_pct), native_endian);
            try appendAttr(gpa, list, NETEM_LOSS.GE, &raw);
        },
    }
    codec.nestEnd(list, nest) catch return error.OptionsTooLong;
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
            if (a.data.len >= 16) {
                nw.packet_overhead = std.mem.readInt(i32, a.data[4..8], native_endian);
                nw.cell_size = std.mem.readInt(u32, a.data[8..12], native_endian);
                nw.cell_overhead = std.mem.readInt(i32, a.data[12..16], native_endian);
            }
        },
        TCA_NETEM.RATE64 => if (a.data.len == 8) {
            nw.rate64 = std.mem.readInt(u64, a.data[0..8], native_endian);
        },
        TCA_NETEM.ECN => if (a.data.len == 4) {
            nw.ecn = std.mem.readInt(u32, a.data[0..4], native_endian) != 0;
        },
        TCA_NETEM.LOSS => {
            var lit: codec.AttrIterator = .{ .buf = a.data };
            // A malformed nest is skipped like any other odd sub-attribute.
            while (lit.next() catch null) |m| switch (m.type) {
                NETEM_LOSS.GI => if (m.data.len >= 20) {
                    var v: [5]u32 = undefined;
                    for (&v, 0..) |*x, i| x.* = std.mem.readInt(u32, m.data[i * 4 ..][0..4], native_endian);
                    nw.loss_gi = v;
                },
                NETEM_LOSS.GE => if (m.data.len >= 16) {
                    var v: [4]u32 = undefined;
                    for (&v, 0..) |*x, i| x.* = std.mem.readInt(u32, m.data[i * 4 ..][0..4], native_endian);
                    nw.loss_ge = v;
                },
                else => {},
            };
        },
        TCA_NETEM.DELAY_DIST => nw.delay_dist_len = @intCast(a.data.len / 2),
        TCA_NETEM.SLOT_DIST => nw.slot_dist_len = @intCast(a.data.len / 2),
        TCA_NETEM.SLOT => if (a.data.len >= tc_netem_slot_len) {
            nw.slot = .{
                .min_delay_ns = std.mem.readInt(i64, a.data[0..8], native_endian),
                .max_delay_ns = std.mem.readInt(i64, a.data[8..16], native_endian),
                .max_packets = std.mem.readInt(i32, a.data[16..20], native_endian),
                .max_bytes = std.mem.readInt(i32, a.data[20..24], native_endian),
                .dist_delay_ns = std.mem.readInt(i64, a.data[24..32], native_endian),
                .dist_jitter_ns = std.mem.readInt(i64, a.data[32..40], native_endian),
            };
        },
        TCA_NETEM.PRNG_SEED => if (a.data.len == 8) {
            nw.prng_seed = std.mem.readInt(u64, a.data[0..8], native_endian);
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
    /// Largest packet the rate tables are sized for (`mtu`). The default is
    /// `tc`'s, 1600 bytes — not the interface MTU.
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
    try ratespec.checkCellLog(c.cell_log);
    try ratespec.checkCellLog(c.ccell_log);
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

    // Default burst: one scheduler tick's worth of bytes at the rate, plus one
    // full packet so the bucket can always hold at least an MTU.
    const hz = if (ps.hz == 0) 1 else ps.hz;
    const burst: u64 = if (c.burst != 0) c.burst else rate64 / hz + c.mtu;
    const cburst: u64 = if (c.cburst != 0) c.cburst else ceil64 / hz + c.mtu;

    var rtab: [ratespec.rate_table_entries]u32 = undefined;
    var ctab: [ratespec.rate_table_entries]u32 = undefined;
    // NB: `tc` builds htb's tables from the **clamped** 32-bit rate, while
    // the buffer timings use the full 64-bit rate (the goldens pin both).
    ratespec.calcRateTable(ps, &rate_spec, &rtab, c.cell_log, c.mtu, c.linklayer, null);
    const buffer_ticks = ps.calcXmitTime(rate64, burst);
    // F10: `calcRateTable`'s 256-entry loop is ~98-100% of this function's
    // cost (A1 audit, measured), and its output depends only on the clamped
    // rate it is fed plus the cell_log override -- both public config, mtu
    // and linklayer already being shared with the rate table above. When
    // `ceil`'s clamped rate and cell_log override match `rate`'s exactly
    // (rate==ceil is the common `tc` invocation the goldens capture, and a
    // >=2^32 rate/ceil pair that both clamp to the same ~0U also qualifies),
    // the loop would recompute byte-identical output, so reuse it instead.
    if (rate_spec.rate == ceil_spec.rate and c.cell_log == c.ccell_log) {
        ctab = rtab;
        ceil_spec.cell_align = rate_spec.cell_align;
        ceil_spec.cell_log = rate_spec.cell_log;
        ceil_spec.linklayer = rate_spec.linklayer;
    } else {
        ratespec.calcRateTable(ps, &ceil_spec, &ctab, c.ccell_log, c.mtu, c.linklayer, null);
    }
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

/// Bytes that drain at `rate` bytes/s within `latency_us`, plus `bucket`. In
/// `f64` on purpose: `tc` computes it in floating point and the goldens pin
/// the truncated result.
fn latencyBound(rate: u64, latency_us: u64, bucket: u32) f64 {
    const drained = @as(f64, @floatFromInt(rate)) * @as(f64, @floatFromInt(latency_us)) /
        ratespec.time_units_per_sec;
    return drained + @as(f64, @floatFromInt(bucket));
}

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
    try ratespec.checkCellLog(t.cell_log);
    try ratespec.checkCellLog(t.pcell_log);

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
        // The queue holds what drains within `latency_us`, plus one bucket;
        // with a peak rate, the tighter of that and the peak-rate bound.
        var queue_bytes = latencyBound(t.rate, t.latency_us, t.burst);
        if (t.peakrate != 0) queue_bytes = @min(queue_bytes, latencyBound(t.peakrate, t.latency_us, t.mtu));
        limit = if (queue_bytes >= @as(f64, std.math.maxInt(u32))) std.math.maxInt(u32) else @intFromFloat(queue_bytes);
    }

    var rtab: [ratespec.rate_table_entries]u32 = undefined;
    ratespec.calcRateTable(ps, &rate_spec, &rtab, t.cell_log, t.mtu, t.linklayer, null);
    // NB: unlike htb, tbf times its buffer with the **clamped** rate.
    const buffer_ticks = ps.calcXmitTime(rate_spec.rate, t.burst);

    var ptab: [ratespec.rate_table_entries]u32 = undefined;
    var mtu_ticks: u32 = 0;
    if (peak_spec.rate != 0) {
        // F10: same reuse as htb's rate/ceil pair above -- identical clamped
        // rate and cell_log override means an identical table.
        if (peak_spec.rate == rate_spec.rate and t.pcell_log == t.cell_log) {
            ptab = rtab;
            peak_spec.cell_align = rate_spec.cell_align;
            peak_spec.cell_log = rate_spec.cell_log;
            peak_spec.linklayer = rate_spec.linklayer;
        } else {
            ratespec.calcRateTable(ps, &peak_spec, &ptab, t.pcell_log, t.mtu, t.linklayer, null);
        }
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
    // Attribute order does not matter to the kernel; this one makes a request
    // byte-identical to the captured `tc` goldens.
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

// ── ingress / clsact ────────────────────────────────────────────────────────

/// The `ingress` qdisc (`sch_ingress`): the attach point for ingress filters
/// and actions. Like `tc qdisc add dev X ingress` it is sent with handle
/// `ffff:` under parent `TC_H_INGRESS` (`Handle.ingress`) and **no
/// `TCA_OPTIONS`** — the caller passes those two handles (see the golden).
pub const Ingress = struct {};

/// The `clsact` qdisc (`sch_ingress`): `ingress` plus an egress attach point,
/// the one eBPF `direct-action` filters hang on. Same wire shape as `Ingress`
/// (handle `ffff:`, parent `TC_H_CLSACT`, kind only, no options).
pub const Clsact = struct {};

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
    // Attribute order does not matter to the kernel; this one makes a request
    // byte-identical to the captured `tc` goldens.
    if (c.bandwidth) |v| try appendAttrU64(gpa, list, TCA_CAKE.BASE_RATE64, v);
    if (c.diffserv) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.DIFFSERV_MODE, @backingInt(v));
    if (c.atm) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.ATM, @backingInt(v));
    if (c.flow_mode) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.FLOW_MODE, @backingInt(v));
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
    if (c.ack_filter) |v| try codec.appendAttrU32(gpa, list, TCA_CAKE.ACK_FILTER, @backingInt(v));
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

// ── classic qdiscs: prio, pfifo/bfifo, sfq, codel, fq ───────────────────────
//
// Layouts read off byte-exact goldens from iproute2 6.19.0 (`goldens.zig`).

/// An attribute whose payload is a few octets, so it cannot overflow the 16-bit length.
fn appendSmallAttr(gpa: std.mem.Allocator, list: *std.ArrayList(u8), attr_type: u16, data: []const u8) std.mem.Allocator.Error!void {
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// `TC_PRIO_MAX + 1`: the size of a priomap.
pub const prio_map_len = 16;
/// The priomap `tc` sends when none is given (`TC_PRIO_*` → band).
pub const prio_default_map: [prio_map_len]u8 = .{ 1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1 };

/// The strict-priority qdisc. The payload is `struct tc_prio_qopt` (bands as a
/// native `i32`, then the 16-octet priomap) followed by an attribute of type
/// `TCA_OPTIONS` that `tc` always appends; it is empty, or holds the empty
/// `TCA_PRIO_MQ` flag for `multiqueue`.
pub const Prio = struct {
    /// `bands N`, 2..16 (`tc` default 3).
    bands: u8 = 3,
    /// `priomap P0 … P15`: the band of each of the 16 `TC_PRIO_*` values; each
    /// must be below `bands`.
    priomap: [prio_map_len]u8 = prio_default_map,
    /// `multiqueue`: map bands to the device's hardware queues (`TCA_PRIO_MQ`).
    multiqueue: bool = false,
};

/// Wire readback of a prio qdisc's options.
pub const PrioWire = struct {
    bands: u32,
    priomap: [prio_map_len]u8,
};

fn appendPrioQopt(list: *std.ArrayList(u8), gpa: std.mem.Allocator, bands: u32, priomap: [prio_map_len]u8) std.mem.Allocator.Error!void {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, bands, native_endian);
    try list.appendSlice(gpa, &raw);
    try list.appendSlice(gpa, &priomap);
}

fn appendPrioOptions(p: Prio, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    if (p.bands < 2 or p.bands > prio_map_len) return error.InvalidPrioBands;
    for (p.priomap) |b| if (b >= p.bands) return error.InvalidPrioBands;
    try appendPrioQopt(list, gpa, p.bands, p.priomap);
    const nest = try codec.nestBegin(gpa, list, TCA.OPTIONS);
    if (p.multiqueue) try appendSmallAttr(gpa, list, TCA_PRIO_MQ, &.{});
    codec.nestEnd(list, nest) catch return error.OptionsTooLong;
}

/// Null when the payload is shorter than `struct tc_prio_qopt` (skipped like any
/// other optional attribute; the kernel never sends one).
pub fn parsePrioOptions(data: []const u8) ?PrioWire {
    if (data.len < 4 + prio_map_len) return null;
    return .{
        .bands = std.mem.readInt(u32, data[0..4], native_endian),
        .priomap = data[4..][0..prio_map_len].*,
    };
}

/// A packet-count FIFO (`pfifo`) or byte-count FIFO (`bfifo`) — the same
/// options (`struct tc_fifo_qopt`, one `u32`), distinguished by the kind.
/// With no `limit` `tc` sends no `TCA_OPTIONS` at all (`carriesOptions`).
pub const Fifo = struct {
    /// `limit N`: packets for `pfifo`, bytes for `bfifo`.
    limit: ?u32 = null,
};

/// Wire readback of a pfifo/bfifo qdisc's options.
pub const FifoWire = struct { limit: u32 };

fn appendFifoOptions(f: Fifo, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) std.mem.Allocator.Error!void {
    var raw: [4]u8 = undefined;
    std.mem.writeInt(u32, &raw, f.limit orelse 0, native_endian);
    try list.appendSlice(gpa, &raw);
}

/// Null when the payload is shorter than `struct tc_fifo_qopt`.
pub fn parseFifoOptions(data: []const u8) ?FifoWire {
    if (data.len < 4) return null;
    return .{ .limit = std.mem.readInt(u32, data[0..4], native_endian) };
}

/// `sizeof(struct tc_sfq_qopt_v1)`: the 20-octet v0 part (quantum, perturb,
/// limit, divisor, flows), depth and headdrop, the RED extension and the
/// trailing `tc_sfqred_stats`.
pub const tc_sfq_qopt_v1_len = 72;

/// The RED part of `sfq` (`redflowlimit`/`min`/`max`/`avpkt`/`burst`/
/// `probability`/`ecn`/`harddrop`), as the **wire fields** of
/// `struct tc_sfq_qopt_v1`. `redparams.deriveSfqRed` derives `wlog`, `plog` and
/// `max_p` from `burst`/`avpkt`/`min`/`max` as `tc` does, or the caller supplies
/// them (the golden shows `burst 55 avpkt 1000 min 30000 max 90000 probability
/// 0.4` as 5, 18, 0 and `max_p` = 0x66666666).
pub const SfqRed = struct {
    /// `redflowlimit` (`limit` in `struct tc_sfq_qopt_v1`).
    flow_limit: u32 = 0,
    qth_min: u32 = 0,
    qth_max: u32 = 0,
    wlog: u8 = 0,
    plog: u8 = 0,
    scell_log: u8 = 0,
    /// `TC_RED_ECN` = 1, `TC_RED_HARDDROP` = 2, `TC_RED_ADAPTATIVE` = 4.
    flags: u8 = 0,
    /// `probability` as a fraction of 2^32.
    max_p: u32 = 0,
};

/// Stochastic fairness queueing. Every field is optional; with none set `tc`
/// sends no `TCA_OPTIONS`, with any set it sends the whole 72-octet
/// `tc_sfq_qopt_v1`, unset fields as 0.
pub const Sfq = struct {
    quantum: ?u32 = null,
    /// `perturb SECONDS`.
    perturb_s: ?i32 = null,
    limit: ?u32 = null,
    divisor: ?u32 = null,
    flows: ?u32 = null,
    depth: ?u32 = null,
    headdrop: ?bool = null,
    red: ?SfqRed = null,
};

/// Wire readback of an sfq qdisc's options (the fields this module models).
pub const SfqWire = struct {
    quantum: u32,
    perturb_s: i32,
    limit: u32,
    divisor: u32,
    flows: u32,
    /// Absent when the payload is the 20-octet v0 form.
    depth: ?u32 = null,
    headdrop: ?u32 = null,
    red: ?SfqRed = null,
};

fn sfqAnySet(q: Sfq) bool {
    return q.quantum != null or q.perturb_s != null or q.limit != null or q.divisor != null or
        q.flows != null or q.depth != null or q.headdrop != null or q.red != null;
}

fn appendSfqOptions(q: Sfq, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) std.mem.Allocator.Error!void {
    var raw: [tc_sfq_qopt_v1_len]u8 = @splat(0);
    std.mem.writeInt(u32, raw[0..4], q.quantum orelse 0, native_endian);
    std.mem.writeInt(i32, raw[4..8], q.perturb_s orelse 0, native_endian);
    std.mem.writeInt(u32, raw[8..12], q.limit orelse 0, native_endian);
    std.mem.writeInt(u32, raw[12..16], q.divisor orelse 0, native_endian);
    std.mem.writeInt(u32, raw[16..20], q.flows orelse 0, native_endian);
    std.mem.writeInt(u32, raw[20..24], q.depth orelse 0, native_endian);
    std.mem.writeInt(u32, raw[24..28], @intFromBool(q.headdrop orelse false), native_endian);
    if (q.red) |r| {
        std.mem.writeInt(u32, raw[28..32], r.flow_limit, native_endian);
        std.mem.writeInt(u32, raw[32..36], r.qth_min, native_endian);
        std.mem.writeInt(u32, raw[36..40], r.qth_max, native_endian);
        raw[40] = r.wlog;
        raw[41] = r.plog;
        raw[42] = r.scell_log;
        raw[43] = r.flags;
        std.mem.writeInt(u32, raw[44..48], r.max_p, native_endian);
    }
    try list.appendSlice(gpa, &raw);
}

/// Null when the payload is shorter than the 20-octet v0 `tc_sfq_qopt`.
pub fn parseSfqOptions(data: []const u8) ?SfqWire {
    if (data.len < 20) return null;
    var w: SfqWire = .{
        .quantum = std.mem.readInt(u32, data[0..4], native_endian),
        .perturb_s = std.mem.readInt(i32, data[4..8], native_endian),
        .limit = std.mem.readInt(u32, data[8..12], native_endian),
        .divisor = std.mem.readInt(u32, data[12..16], native_endian),
        .flows = std.mem.readInt(u32, data[16..20], native_endian),
    };
    if (data.len >= 28) {
        w.depth = std.mem.readInt(u32, data[20..24], native_endian);
        w.headdrop = std.mem.readInt(u32, data[24..28], native_endian);
    }
    if (data.len >= 48) w.red = .{
        .flow_limit = std.mem.readInt(u32, data[28..32], native_endian),
        .qth_min = std.mem.readInt(u32, data[32..36], native_endian),
        .qth_max = std.mem.readInt(u32, data[36..40], native_endian),
        .wlog = data[40],
        .plog = data[41],
        .scell_log = data[42],
        .flags = data[43],
        .max_p = std.mem.readInt(u32, data[44..48], native_endian),
    };
    return w;
}

/// Controlled-delay AQM. Every field is optional (`null` omits the attribute);
/// `tc codel` with nothing sends an empty options nest.
pub const Codel = struct {
    /// Hard packet limit (`limit`).
    limit: ?u32 = null,
    /// `interval`, microseconds.
    interval_us: ?u32 = null,
    /// `target`, microseconds.
    target_us: ?u32 = null,
    /// `ecn` / `noecn`.
    ecn: ?bool = null,
    /// `ce_threshold`, microseconds.
    ce_threshold_us: ?u32 = null,
};

/// Wire readback of a codel qdisc's options.
pub const CodelWire = struct {
    limit: ?u32 = null,
    interval_us: ?u32 = null,
    target_us: ?u32 = null,
    ecn: ?u32 = null,
    ce_threshold_us: ?u32 = null,
};

fn appendCodelOptions(c: Codel, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    // Order of the goldens: LIMIT, INTERVAL, TARGET, ECN, CE_THRESHOLD.
    if (c.limit) |v| try codec.appendAttrU32(gpa, list, TCA_CODEL.LIMIT, v);
    if (c.interval_us) |v| try codec.appendAttrU32(gpa, list, TCA_CODEL.INTERVAL, v);
    if (c.target_us) |v| try codec.appendAttrU32(gpa, list, TCA_CODEL.TARGET, v);
    if (c.ecn) |v| try codec.appendAttrU32(gpa, list, TCA_CODEL.ECN, @intFromBool(v));
    if (c.ce_threshold_us) |v| try codec.appendAttrU32(gpa, list, TCA_CODEL.CE_THRESHOLD, v);
}

pub fn parseCodelOptions(data: []const u8) codec.Error!CodelWire {
    var w: CodelWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| {
        if (a.data.len != 4) continue;
        const v = std.mem.readInt(u32, a.data[0..4], native_endian);
        switch (a.type) {
            TCA_CODEL.LIMIT => w.limit = v,
            TCA_CODEL.INTERVAL => w.interval_us = v,
            TCA_CODEL.TARGET => w.target_us = v,
            TCA_CODEL.ECN => w.ecn = v,
            TCA_CODEL.CE_THRESHOLD => w.ce_threshold_us = v,
            else => {},
        }
    }
    return w;
}

/// The fair-queue pacing qdisc (`sch_fq`). Every field is optional; `tc fq`
/// with nothing sends an empty options nest. Rates are bytes per second
/// (`maxrate 10mbit` = 1250000, a `u32` on the wire), times are as noted.
pub const Fq = struct {
    /// `limit`, packets.
    limit: ?u32 = null,
    flow_limit: ?u32 = null,
    quantum: ?u32 = null,
    initial_quantum: ?u32 = null,
    /// `pacing` / `nopacing` (`TCA_FQ_RATE_ENABLE`).
    pacing: ?bool = null,
    /// `defrate`, bytes per second: the pacing rate of a flow that has none
    /// (`TCA_FQ_FLOW_DEFAULT_RATE`).
    defrate: ?u32 = null,
    /// `maxrate`, bytes per second.
    maxrate: ?u32 = null,
    /// log2 of `buckets` (`buckets 2048` is 11); sent first.
    buckets_log: ?u32 = null,
    /// `refill_delay`, microseconds.
    refill_delay_us: ?u32 = null,
    orphan_mask: ?u32 = null,
    /// `low_rate_threshold`, bytes per second.
    low_rate_threshold: ?u32 = null,
    /// `ce_threshold`, microseconds.
    ce_threshold_us: ?u32 = null,
    /// `timer_slack`, nanoseconds.
    timer_slack_ns: ?u32 = null,
    /// `horizon`, microseconds.
    horizon_us: ?u32 = null,
    /// `horizon_drop` (true) / `horizon_cap` (false).
    horizon_drop: ?bool = null,
    /// `bands 3 priomap …` (`TCA_FQ_PRIO`, bands fixed at 3).
    priomap: ?[prio_map_len]u8 = null,
    /// `weights W1 W2 W3`.
    weights: ?[3]i32 = null,
    /// `offload_horizon`, microseconds.
    offload_horizon_us: ?u32 = null,
};

/// Wire readback of an fq qdisc's options.
pub const FqWire = struct {
    limit: ?u32 = null,
    flow_limit: ?u32 = null,
    quantum: ?u32 = null,
    initial_quantum: ?u32 = null,
    pacing: ?u32 = null,
    defrate: ?u32 = null,
    maxrate: ?u32 = null,
    buckets_log: ?u32 = null,
    refill_delay_us: ?u32 = null,
    orphan_mask: ?u32 = null,
    low_rate_threshold: ?u32 = null,
    ce_threshold_us: ?u32 = null,
    timer_slack_ns: ?u32 = null,
    horizon_us: ?u32 = null,
    horizon_drop: ?u8 = null,
    priomap: ?[prio_map_len]u8 = null,
    weights: ?[3]i32 = null,
    offload_horizon_us: ?u32 = null,
};

fn appendFqOptions(f: Fq, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    // The order iproute2 6.19 sends (goldens): BUCKETS_LOG, PLIMIT, FLOW_PLIMIT,
    // QUANTUM, INITIAL_QUANTUM, RATE_ENABLE, FLOW_MAX_RATE, LOW_RATE_THRESHOLD,
    // FLOW_REFILL_DELAY, ORPHAN_MASK, CE_THRESHOLD, TIMER_SLACK, HORIZON,
    // HORIZON_DROP, PRIO, WEIGHTS, OFFLOAD_HORIZON.
    if (f.buckets_log) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.BUCKETS_LOG, v);
    if (f.limit) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.PLIMIT, v);
    if (f.flow_limit) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.FLOW_PLIMIT, v);
    if (f.quantum) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.QUANTUM, v);
    if (f.initial_quantum) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.INITIAL_QUANTUM, v);
    if (f.pacing) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.RATE_ENABLE, @intFromBool(v));
    if (f.defrate) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.FLOW_DEFAULT_RATE, v);
    if (f.maxrate) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.FLOW_MAX_RATE, v);
    if (f.low_rate_threshold) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.LOW_RATE_THRESHOLD, v);
    if (f.refill_delay_us) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.FLOW_REFILL_DELAY, v);
    if (f.orphan_mask) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.ORPHAN_MASK, v);
    if (f.ce_threshold_us) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.CE_THRESHOLD, v);
    if (f.timer_slack_ns) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.TIMER_SLACK, v);
    if (f.horizon_us) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.HORIZON, v);
    if (f.horizon_drop) |v| try appendSmallAttr(gpa, list, TCA_FQ.HORIZON_DROP, &.{@intFromBool(v)});
    if (f.priomap) |m| {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(gpa);
        try appendPrioQopt(&raw, gpa, 3, m);
        try appendSmallAttr(gpa, list, TCA_FQ.PRIO, raw.items);
    }
    if (f.weights) |w| {
        var raw: [12]u8 = undefined;
        for (w, 0..) |x, i| std.mem.writeInt(i32, raw[i * 4 ..][0..4], x, native_endian);
        try appendSmallAttr(gpa, list, TCA_FQ.WEIGHTS, &raw);
    }
    if (f.offload_horizon_us) |v| try codec.appendAttrU32(gpa, list, TCA_FQ.OFFLOAD_HORIZON, v);
}

pub fn parseFqOptions(data: []const u8) codec.Error!FqWire {
    var w: FqWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| {
        if (a.data.len == 4) {
            const v = std.mem.readInt(u32, a.data[0..4], native_endian);
            switch (a.type) {
                TCA_FQ.PLIMIT => w.limit = v,
                TCA_FQ.FLOW_PLIMIT => w.flow_limit = v,
                TCA_FQ.QUANTUM => w.quantum = v,
                TCA_FQ.INITIAL_QUANTUM => w.initial_quantum = v,
                TCA_FQ.RATE_ENABLE => w.pacing = v,
                TCA_FQ.FLOW_DEFAULT_RATE => w.defrate = v,
                TCA_FQ.FLOW_MAX_RATE => w.maxrate = v,
                TCA_FQ.BUCKETS_LOG => w.buckets_log = v,
                TCA_FQ.FLOW_REFILL_DELAY => w.refill_delay_us = v,
                TCA_FQ.ORPHAN_MASK => w.orphan_mask = v,
                TCA_FQ.LOW_RATE_THRESHOLD => w.low_rate_threshold = v,
                TCA_FQ.CE_THRESHOLD => w.ce_threshold_us = v,
                TCA_FQ.TIMER_SLACK => w.timer_slack_ns = v,
                TCA_FQ.HORIZON => w.horizon_us = v,
                TCA_FQ.OFFLOAD_HORIZON => w.offload_horizon_us = v,
                else => {},
            }
        } else switch (a.type) {
            TCA_FQ.HORIZON_DROP => if (a.data.len == 1) {
                w.horizon_drop = a.data[0];
            },
            TCA_FQ.PRIO => if (a.data.len >= 4 + prio_map_len) {
                w.priomap = a.data[4..][0..prio_map_len].*;
            },
            TCA_FQ.WEIGHTS => if (a.data.len == 12) {
                var x: [3]i32 = undefined;
                for (&x, 0..) |*e, i| e.* = std.mem.readInt(i32, a.data[i * 4 ..][0..4], native_endian);
                w.weights = x;
            },
            else => {},
        }
    }
    return w;
}

// ── hfsc and red ─────────────────────────────────────────────────────────────

/// The hierarchical fair-service-curve qdisc (`hfsc`). Its qdisc options are one
/// `struct tc_hfsc_qopt` (a `u16` `defcls`); the curves live on the classes,
/// which this module does not model.
pub const Hfsc = struct {
    /// `default N`: the class id (minor) that unclassified packets go to; 0 = none.
    default_class: u16 = 0,
};

/// Wire readback of an hfsc qdisc's options.
pub const HfscWire = struct { default_class: u16 };

fn appendHfscOptions(h: Hfsc, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) std.mem.Allocator.Error!void {
    var raw: [2]u8 = undefined;
    std.mem.writeInt(u16, &raw, h.default_class, native_endian);
    try list.appendSlice(gpa, &raw);
}

/// Null when the payload is shorter than `struct tc_hfsc_qopt`.
pub fn parseHfscOptions(data: []const u8) ?HfscWire {
    if (data.len < 2) return null;
    return .{ .default_class = std.mem.readInt(u16, data[0..2], native_endian) };
}

/// `TC_RED_ECN`, `TC_RED_HARDDROP`, `TC_RED_ADAPTATIVE`, `TC_RED_NODROP`.
pub const red_flag_ecn: u8 = 1;
pub const red_flag_harddrop: u8 = 2;
pub const red_flag_adaptative: u8 = 4;
pub const red_flag_nodrop: u8 = 8;
/// `TC_RED_SUPPORTED_FLAGS`: the selector `tc` sends with the flags value.
pub const red_supported_flags: u32 = 0x0f;
/// `RED_STAB_SIZE`.
pub const red_stab_len = 256;

/// Random early detection (`red`). `tc` derives `wlog`, `plog`, `scell_log` and
/// the 256-octet idle-damping table `stab` from `burst`/`avpkt`/`probability`
/// (and `bandwidth`); `redparams.deriveRed` does the same, or the caller
/// supplies them (the kernel refuses a `red` without `stab`). `max_p` is
/// `probability * 2^32`.
pub const Red = struct {
    /// `limit`, bytes.
    limit: u32,
    /// `min`, bytes.
    qth_min: u32,
    /// `max`, bytes.
    qth_max: u32,
    wlog: u8,
    plog: u8,
    scell_log: u8,
    /// `TCA_RED_STAB`: the idle-damping table, `RED_STAB_SIZE` octets.
    stab: *const [red_stab_len]u8,
    /// `TCA_RED_MAX_P`; null omits it.
    max_p: ?u32 = null,
    /// `red_flag_*` bits (`ecn`, `harddrop`, `adaptive`, `nodrop`), sent as
    /// `TCA_RED_FLAGS` with `red_supported_flags` as selector, as `tc` does.
    flags: u8 = 0,
};

/// Wire readback of a red qdisc's options (the kernel does not dump `stab`).
pub const RedWire = struct {
    limit: u32 = 0,
    qth_min: u32 = 0,
    qth_max: u32 = 0,
    wlog: u8 = 0,
    plog: u8 = 0,
    scell_log: u8 = 0,
    /// The `flags` octet of `struct tc_red_qopt` (historic flags).
    qopt_flags: u8 = 0,
    max_p: ?u32 = null,
    /// `TCA_RED_FLAGS` value, when sent.
    flags: ?u32 = null,
};

const RedAttrError = std.mem.Allocator.Error || error{AttrTooLong};

fn redAttrErr(e: RedAttrError) EncodeError {
    return switch (e) {
        error.AttrTooLong => error.OptionsTooLong,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn appendRedOptions(r: Red, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    var parms: [16]u8 = undefined;
    std.mem.writeInt(u32, parms[0..4], r.limit, native_endian);
    std.mem.writeInt(u32, parms[4..8], r.qth_min, native_endian);
    std.mem.writeInt(u32, parms[8..12], r.qth_max, native_endian);
    parms[12] = r.wlog;
    parms[13] = r.plog;
    parms[14] = r.scell_log;
    parms[15] = 0; // tc keeps the flags out of the struct and sends them as TCA_RED_FLAGS
    codec.appendAttr(gpa, list, TCA_RED.PARMS, &parms) catch |e| return redAttrErr(e);
    codec.appendAttr(gpa, list, TCA_RED.STAB, r.stab) catch |e| return redAttrErr(e);
    if (r.max_p) |v| codec.appendAttrU32(gpa, list, TCA_RED.MAX_P, v) catch |e| return redAttrErr(e);
    var fl: [8]u8 = undefined;
    std.mem.writeInt(u32, fl[0..4], r.flags, native_endian);
    std.mem.writeInt(u32, fl[4..8], red_supported_flags, native_endian);
    codec.appendAttr(gpa, list, TCA_RED.FLAGS, &fl) catch |e| return redAttrErr(e);
}

pub fn parseRedOptions(data: []const u8) codec.Error!RedWire {
    var w: RedWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_RED.PARMS => if (a.data.len >= 16) {
            w.limit = std.mem.readInt(u32, a.data[0..4], native_endian);
            w.qth_min = std.mem.readInt(u32, a.data[4..8], native_endian);
            w.qth_max = std.mem.readInt(u32, a.data[8..12], native_endian);
            w.wlog = a.data[12];
            w.plog = a.data[13];
            w.scell_log = a.data[14];
            w.qopt_flags = a.data[15];
        },
        TCA_RED.MAX_P => if (a.data.len == 4) {
            w.max_p = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        TCA_RED.FLAGS => if (a.data.len == 8) {
            w.flags = std.mem.readInt(u32, a.data[0..4], native_endian);
        },
        else => {},
    };
    return w;
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
    ingress: Ingress,
    clsact: Clsact,
    cake: Cake,
    prio: Prio,
    pfifo: Fifo,
    bfifo: Fifo,
    sfq: Sfq,
    codel: Codel,
    fq: Fq,
    hfsc: Hfsc,
    red: Red,
    pfifo_fast: PfifoFast,
    pfifo_head_drop: Fifo,
    raw: Raw,

    pub fn kind(self: QdiscSpec) []const u8 {
        return switch (self) {
            .netem => kind_netem,
            .htb => kind_htb,
            .tbf => kind_tbf,
            .fq_codel => kind_fq_codel,
            .mq => kind_mq,
            .ingress => kind_ingress,
            .clsact => kind_clsact,
            .cake => kind_cake,
            .prio => kind_prio,
            .pfifo => kind_pfifo,
            .bfifo => kind_bfifo,
            .sfq => kind_sfq,
            .codel => kind_codel,
            .fq => kind_fq,
            .hfsc => kind_hfsc,
            .red => kind_red,
            .pfifo_fast => kind_pfifo_fast,
            .pfifo_head_drop => kind_pfifo_head_drop,
            .raw => |r| r.kind,
        };
    }

    /// Whether this kind puts a `TCA_OPTIONS` attribute on the wire at all.
    /// `mq`, `ingress` and `clsact` send **none** — not even an empty nest
    /// (`mq`: the kernel auto-populates its per-queue children); a byte-exact
    /// request must omit the attribute entirely. Every other kind carries an options nest (empty
    /// when no knobs are set, exactly like `tc`).
    pub fn carriesOptions(self: QdiscSpec) bool {
        return switch (self) {
            .mq, .ingress, .clsact => false,
            // `tc pfifo`/`bfifo`/`sfq` with no argument send no options at all.
            .pfifo, .bfifo, .pfifo_head_drop => |f| f.limit != null,
            // `pfifo_fast` is a kind name only: the kernel sets its bands.
            .pfifo_fast => false,
            .sfq => |q| sfqAnySet(q),
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
            .mq, .ingress, .clsact => {}, // no options; carriesOptions() gates the nest away
            .cake => |c| try appendCakeOptions(c, gpa, list),
            .prio => |p| try appendPrioOptions(p, gpa, list),
            .pfifo, .bfifo, .pfifo_head_drop => |f| try appendFifoOptions(f, gpa, list),
            .pfifo_fast => {}, // no options; carriesOptions() gates the nest away
            .sfq => |q| try appendSfqOptions(q, gpa, list),
            .codel => |c| try appendCodelOptions(c, gpa, list),
            .fq => |f| try appendFqOptions(f, gpa, list),
            .hfsc => |h| try appendHfscOptions(h, gpa, list),
            .red => |r| try appendRedOptions(r, gpa, list),
            .raw => |r| {
                if (r.options.len > std.math.maxInt(u16)) return error.OptionsTooLong;
                try list.appendSlice(gpa, r.options);
                try list.appendNTimes(gpa, 0, codec.alignUp(r.options.len) - r.options.len);
            },
        }
    }
};

/// `pfifo_fast` — the default root qdisc: a kind name only, the kernel sets
/// its three bands and the TOS priomap (`tc qdisc add … pfifo_fast`).
pub const PfifoFast = struct {};

// ── hfsc classes ────────────────────────────────────────────────────────────

/// `TCA_HFSC_*` — the class-level attributes.
pub const TCA_HFSC = struct {
    pub const UNSPEC: u16 = 0;
    pub const RSC: u16 = 1;
    pub const FSC: u16 = 2;
    pub const USC: u16 = 3;
};

/// `sizeof(struct tc_service_curve)`.
pub const tc_service_curve_len = 12;

/// `struct tc_service_curve`: slope `m1` bytes/s for the first `d_us`
/// microseconds, then `m2` bytes/s (`tc … rt m1 2mbit d 10ms m2 1mbit`; a
/// plain `rate R` is `m2 = R` with the rest 0).
pub const ServiceCurve = struct {
    m1: u32 = 0,
    d_us: u32 = 0,
    m2: u32 = 0,
};

/// An hfsc class: its real-time (`rt`), link-sharing (`ls`) and upper-limit
/// (`ul`) curves. `tc … sc …` sets the real-time and link-sharing curves
/// at once. Sent in the order `rsc`, `fsc`, `usc`.
pub const HfscClass = struct {
    rsc: ?ServiceCurve = null,
    fsc: ?ServiceCurve = null,
    usc: ?ServiceCurve = null,
};

pub const HfscClassWire = struct {
    rsc: ?ServiceCurve = null,
    fsc: ?ServiceCurve = null,
    usc: ?ServiceCurve = null,
};

fn encodeCurve(c: ServiceCurve) [tc_service_curve_len]u8 {
    var raw: [tc_service_curve_len]u8 = undefined;
    std.mem.writeInt(u32, raw[0..4], c.m1, native_endian);
    std.mem.writeInt(u32, raw[4..8], c.d_us, native_endian);
    std.mem.writeInt(u32, raw[8..12], c.m2, native_endian);
    return raw;
}

fn decodeCurve(data: []const u8) ?ServiceCurve {
    if (data.len < tc_service_curve_len) return null;
    return .{
        .m1 = std.mem.readInt(u32, data[0..4], native_endian),
        .d_us = std.mem.readInt(u32, data[4..8], native_endian),
        .m2 = std.mem.readInt(u32, data[8..12], native_endian),
    };
}

fn appendHfscClassOptions(c: HfscClass, gpa: std.mem.Allocator, list: *std.ArrayList(u8)) EncodeError!void {
    if (c.rsc) |v| try appendAttr(gpa, list, TCA_HFSC.RSC, &encodeCurve(v));
    if (c.fsc) |v| try appendAttr(gpa, list, TCA_HFSC.FSC, &encodeCurve(v));
    if (c.usc) |v| try appendAttr(gpa, list, TCA_HFSC.USC, &encodeCurve(v));
}

pub fn parseHfscClassOptions(data: []const u8) codec.Error!HfscClassWire {
    var w: HfscClassWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_HFSC.RSC => w.rsc = decodeCurve(a.data),
        TCA_HFSC.FSC => w.fsc = decodeCurve(a.data),
        TCA_HFSC.USC => w.usc = decodeCurve(a.data),
        else => {},
    };
    return w;
}

// ── stab (size tables) ──────────────────────────────────────────────────────

/// `TCA_STAB_*`, nested in `TCA_STAB`.
pub const TCA_STAB = struct {
    pub const UNSPEC: u16 = 0;
    pub const BASE: u16 = 1;
    pub const DATA: u16 = 2;
};

/// `sizeof(struct tc_sizespec)`.
pub const tc_sizespec_len = 24;

/// `tc_sizespec.linklayer` as `tc stab` sends it: 0 when none is named.
pub const StabLinkLayer = enum(u32) {
    unspec = 0,
    ethernet = 1,
    atm = 2,
    _,
};

/// A packet-size table attached to a qdisc (`tc qdisc add … stab overhead 24
/// linklayer atm mtu 1500 tsize 128 mpu 64 …`): the kernel adds `overhead`
/// to every packet's length and looks the result up in a table, so the
/// qdisc accounts for ATM cells or link framing.
pub const Stab = struct {
    /// Per-packet overhead in bytes (may be negative).
    overhead: i32 = 0,
    linklayer: StabLinkLayer = .unspec,
    /// Minimum packet unit: shorter packets count as this long.
    mpu: u32 = 0,
    /// The largest packet size the table covers.
    mtu: u32 = 2047,
    /// How many table entries.
    tsize: u32 = 512,
};

/// Wire readback of `TCA_STAB`.
pub const StabWire = struct {
    cell_log: u8 = 0,
    size_log: u8 = 0,
    cell_align: i16 = 0,
    overhead: i32 = 0,
    linklayer: u32 = 0,
    mpu: u32 = 0,
    mtu: u32 = 0,
    tsize: u32 = 0,
    /// How many 16-bit entries `TCA_STAB_DATA` carried (0: none).
    table_len: u16 = 0,
};

/// The table is only sent when sizes need adjusting: for an ATM link layer or
/// a minimum packet unit; plain ethernet framing is the overhead alone.
fn stabNeedsTable(s: Stab) bool {
    return s.linklayer == .atm or s.mpu != 0;
}

/// The size a packet of `size` bytes counts as in the table.
fn stabAdjust(s: Stab, size: u64) u64 {
    var v = size;
    if (v < s.mpu) v = s.mpu;
    if (s.linklayer == .atm) v = (v + 47) / 48 * 53; // whole 53-byte ATM cells
    return v;
}

fn appendStab(gpa: std.mem.Allocator, list: *std.ArrayList(u8), s: Stab) EncodeError!void {
    const table = stabNeedsTable(s);
    if (table and (s.mtu == 0 or s.tsize == 0 or s.tsize > (std.math.maxInt(u16) - 64) / 2)) return error.InvalidStab;
    var base: [tc_sizespec_len]u8 = @splat(0);
    var cell_log: u6 = 0;
    var size_log: u6 = 0;
    if (table) {
        // The smallest cell shift that lets `tsize` entries cover `mtu`.
        while (cell_log < 31 and (@as(u64, s.mtu) >> cell_log) >= s.tsize) cell_log += 1;
        // The smallest entry shift that keeps the largest entry in 16 bits.
        const biggest = stabAdjust(s, @as(u64, s.tsize) << cell_log);
        while ((biggest >> size_log) > std.math.maxInt(u16)) size_log += 1;
        base[0] = cell_log;
        base[1] = size_log;
        std.mem.writeInt(i16, base[2..4], -1, native_endian);
        std.mem.writeInt(u32, base[16..20], s.mtu, native_endian);
        std.mem.writeInt(u32, base[20..24], s.tsize, native_endian);
        std.mem.writeInt(u32, base[12..16], s.mpu, native_endian);
    }
    std.mem.writeInt(i32, base[4..8], s.overhead, native_endian);
    std.mem.writeInt(u32, base[8..12], @backingInt(s.linklayer), native_endian);
    if (!table) {
        // `mpu`, `mtu` and `tsize` stay 0 without a table.
    }
    const nest = try codec.nestBegin(gpa, list, TCA.STAB);
    try appendAttr(gpa, list, TCA_STAB.BASE, &base);
    if (table) {
        const raw = try gpa.alloc(u8, s.tsize * 2);
        defer gpa.free(raw);
        var i: u32 = 0;
        while (i < s.tsize) : (i += 1) {
            const entry = stabAdjust(s, (@as(u64, i) + 1) << cell_log) >> size_log;
            std.mem.writeInt(u16, raw[i * 2 ..][0..2], @intCast(entry), native_endian);
        }
        try appendAttr(gpa, list, TCA_STAB.DATA, raw);
    }
    codec.nestEnd(list, nest) catch return error.OptionsTooLong;
}

/// Append `TCA_STAB` for `message.buildQdiscSet` (after `TCA_OPTIONS`).
pub fn appendStabAttr(gpa: std.mem.Allocator, list: *std.ArrayList(u8), s: Stab) EncodeError!void {
    return appendStab(gpa, list, s);
}

pub fn parseStab(data: []const u8) codec.Error!StabWire {
    var w: StabWire = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_STAB.BASE => if (a.data.len >= tc_sizespec_len) {
            w.cell_log = a.data[0];
            w.size_log = a.data[1];
            w.cell_align = std.mem.readInt(i16, a.data[2..4], native_endian);
            w.overhead = std.mem.readInt(i32, a.data[4..8], native_endian);
            w.linklayer = std.mem.readInt(u32, a.data[8..12], native_endian);
            w.mpu = std.mem.readInt(u32, a.data[12..16], native_endian);
            w.mtu = std.mem.readInt(u32, a.data[16..20], native_endian);
            w.tsize = std.mem.readInt(u32, a.data[20..24], native_endian);
        },
        TCA_STAB.DATA => w.table_len = @intCast(@min(a.data.len / 2, std.math.maxInt(u16))),
        else => {},
    };
    return w;
}

/// What to attach as a **class** (`RTM_NEWTCLASS`).
pub const ClassSpec = union(enum) {
    htb: HtbClass,
    hfsc: HfscClass,
    raw: Raw,

    pub fn kind(self: ClassSpec) []const u8 {
        return switch (self) {
            .htb => kind_htb,
            .hfsc => kind_hfsc,
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
            .hfsc => |c| try appendHfscClassOptions(c, gpa, list),
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

/// The counters a dumped qdisc or class carries (`tc -s`). Decoded from
/// `TCA_STATS2` (`gnet_stats_basic`, `_queue`, `_rate_est[64]`, the 64-bit
/// `PKT64` packet count when present) or, when the kernel sent no `STATS2`,
/// from the legacy `TCA_STATS` (`struct tc_stats`, which has no `requeues`).
/// A sub-attribute shorter than its struct is ignored (like per-action stats).
pub const Stats = struct {
    bytes: u64 = 0,
    packets: u64 = 0,
    /// `TCA_STATS_BASIC_HW`: what the hardware offload counted.
    hw_bytes: u64 = 0,
    hw_packets: u64 = 0,
    qlen: u32 = 0,
    backlog: u32 = 0,
    drops: u32 = 0,
    requeues: u32 = 0,
    overlimits: u32 = 0,
    /// Rate estimator (`RATE_EST64` wins over `RATE_EST`).
    bps: u64 = 0,
    pps: u64 = 0,
};

/// `struct tc_fq_codel_qd_stats` (the qdisc half of `TCA_XSTATS`, type
/// `TCA_FQ_CODEL_XSTATS_QDISC`).
pub const FqCodelXstats = struct {
    maxpacket: u32,
    drop_overlimit: u32,
    ecn_mark: u32,
    new_flow_count: u32,
    new_flows_len: u32,
    old_flows_len: u32,
    ce_mark: u32,
    memory_usage: u32,
    drop_overmemory: u32,
};

const fq_codel_xstats_qdisc: u32 = 0; // TCA_FQ_CODEL_XSTATS_QDISC
const fq_codel_xstats_class: u32 = 1; // TCA_FQ_CODEL_XSTATS_CLASS
const fq_codel_xstats_len = 4 + 9 * 4; // type + tc_fq_codel_qd_stats
const tc_stats_len = 36; // struct tc_stats, without its tail padding

fn rd32(d: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, d[off..][0..4], native_endian);
}

fn rd64(d: []const u8, off: usize) u64 {
    return std.mem.readInt(u64, d[off..][0..8], native_endian);
}

/// Decode a `TCA_STATS2` nest; null when it held no usable basic/queue/rate
/// counter.
fn parseStats2(data: []const u8) codec.Error!?Stats {
    var s: Stats = .{};
    var seen = false;
    var have_pkt64 = false;
    var have_rate64 = false;
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        // struct gnet_stats_basic { u64 bytes; u32 packets; } (16 on the wire,
        // tail padding).
        TCA_STATS2.BASIC => if (a.data.len >= 12) {
            s.bytes = rd64(a.data, 0);
            if (!have_pkt64) s.packets = rd32(a.data, 8);
            seen = true;
        },
        TCA_STATS2.BASIC_HW => if (a.data.len >= 12) {
            s.hw_bytes = rd64(a.data, 0);
            s.hw_packets = rd32(a.data, 8);
        },
        // struct gnet_stats_queue { qlen, backlog, drops, requeues, overlimits }
        TCA_STATS2.QUEUE => if (a.data.len >= 20) {
            s.qlen = rd32(a.data, 0);
            s.backlog = rd32(a.data, 4);
            s.drops = rd32(a.data, 8);
            s.requeues = rd32(a.data, 12);
            s.overlimits = rd32(a.data, 16);
            seen = true;
        },
        TCA_STATS2.RATE_EST => if (a.data.len >= 8 and !have_rate64) {
            s.bps = rd32(a.data, 0);
            s.pps = rd32(a.data, 4);
            seen = true;
        },
        TCA_STATS2.RATE_EST64 => if (a.data.len >= 16) {
            s.bps = rd64(a.data, 0);
            s.pps = rd64(a.data, 8);
            have_rate64 = true;
            seen = true;
        },
        // 64-bit packet counter: authoritative whatever the attribute order.
        TCA_STATS2.PKT64 => if (a.data.len >= 8) {
            s.packets = rd64(a.data, 0);
            have_pkt64 = true;
        },
        else => {},
    };
    return if (seen) s else null;
}

/// Decode the legacy `TCA_STATS` (`struct tc_stats`).
fn parseLegacyStats(data: []const u8) ?Stats {
    if (data.len < tc_stats_len) return null;
    return .{
        .bytes = rd64(data, 0),
        .packets = rd32(data, 8),
        .drops = rd32(data, 12),
        .overlimits = rd32(data, 16),
        .bps = rd32(data, 20),
        .pps = rd32(data, 24),
        .qlen = rd32(data, 28),
        .backlog = rd32(data, 32),
    };
}

/// `TCA_STATS2` if it decoded to something, else the legacy `TCA_STATS`.
fn pickStats(stats2: ?[]const u8, legacy: ?[]const u8) codec.Error!?Stats {
    if (stats2) |d| if (try parseStats2(d)) |s| return s;
    if (legacy) |d| return parseLegacyStats(d);
    return null;
}

/// `struct tc_htb_xstats` — an htb class's borrowing counters.
pub const HtbXstats = struct {
    lends: u32,
    borrows: u32,
    giants: u32,
    tokens: i32,
    ctokens: i32,
};

/// `struct tc_hfsc_stats` — an hfsc class's service counters.
pub const HfscXstats = struct {
    work: u64,
    rtwork: u64,
    period: u32,
    level: u32,
};

/// `struct tc_red_xstats`.
pub const RedXstats = struct {
    early: u32,
    pdrop: u32,
    other: u32,
    marked: u32,
};

/// `struct tc_codel_xstats`.
pub const CodelXstats = struct {
    maxpacket: u32,
    count: u32,
    lastcount: u32,
    ldelay: u32,
    drop_next: i32,
    drop_overlimit: u32,
    ecn_mark: u32,
    dropping: u32,
    ce_mark: u32,
};

/// `struct tc_fq_codel_cl_stats` — one fq_codel flow (the class half of
/// `TCA_XSTATS`, type `TCA_FQ_CODEL_XSTATS_CLASS`).
pub const FqCodelClassXstats = struct {
    deficit: i32,
    ldelay: u32,
    count: u32,
    lastcount: u32,
    dropping: u32,
    drop_next: i32,
};

/// `TCA_CAKE_STATS_*`, the figures nested in `TCA_STATS2`'s `TCA_STATS_APP`
/// (attribute 0 is unused, 1 is the 64-bit alignment pad).
pub const TCA_CAKE_STATS = struct {
    pub const PAD: u16 = 1;
    pub const CAPACITY_ESTIMATE64: u16 = 2;
    pub const MEMORY_LIMIT: u16 = 3;
    pub const MEMORY_USED: u16 = 4;
    pub const AVG_NETOFF: u16 = 5;
    pub const MIN_NETLEN: u16 = 6;
    pub const MAX_NETLEN: u16 = 7;
    pub const MIN_ADJLEN: u16 = 8;
    pub const MAX_ADJLEN: u16 = 9;
    pub const TIN_STATS: u16 = 10;
    pub const DEFICIT: u16 = 11;
    pub const COBALT_COUNT: u16 = 12;
    pub const DROPPING: u16 = 13;
    pub const DROP_NEXT_US: u16 = 14;
    pub const P_DROP: u16 = 15;
    pub const BLUE_TIMER_US: u16 = 16;
};

/// `TCA_CAKE_TIN_STATS_*` (nested per tin in `TCA_CAKE_STATS_TIN_STATS`).
pub const TCA_CAKE_TIN_STATS = struct {
    pub const PAD: u16 = 1;
    pub const SENT_PACKETS: u16 = 2;
    pub const SENT_BYTES64: u16 = 3;
    pub const DROPPED_PACKETS: u16 = 4;
    pub const DROPPED_BYTES64: u16 = 5;
    pub const ACKS_DROPPED_PACKETS: u16 = 6;
    pub const ACKS_DROPPED_BYTES64: u16 = 7;
    pub const ECN_MARKED_PACKETS: u16 = 8;
    pub const ECN_MARKED_BYTES64: u16 = 9;
    pub const BACKLOG_PACKETS: u16 = 10;
    pub const BACKLOG_BYTES: u16 = 11;
    pub const THRESHOLD_RATE64: u16 = 12;
    pub const TARGET_US: u16 = 13;
    pub const INTERVAL_US: u16 = 14;
    pub const WAY_INDIRECT_HITS: u16 = 15;
    pub const WAY_MISSES: u16 = 16;
    pub const WAY_COLLISIONS: u16 = 17;
    pub const PEAK_DELAY_US: u16 = 18;
    pub const AVG_DELAY_US: u16 = 19;
    pub const BASE_DELAY_US: u16 = 20;
    pub const SPARSE_FLOWS: u16 = 21;
    pub const BULK_FLOWS: u16 = 22;
    pub const UNRESPONSIVE_FLOWS: u16 = 23;
    pub const MAX_SKBLEN: u16 = 24;
    pub const FLOW_QUANTUM: u16 = 25;
};

/// One cake tin's counters (`TCA_CAKE_TIN_STATS_*`); an attribute the kernel
/// did not send stays 0.
pub const CakeTinStats = struct {
    sent_packets: u32 = 0,
    sent_bytes: u64 = 0,
    dropped_packets: u32 = 0,
    dropped_bytes: u64 = 0,
    acks_dropped_packets: u32 = 0,
    acks_dropped_bytes: u64 = 0,
    ecn_marked_packets: u32 = 0,
    ecn_marked_bytes: u64 = 0,
    backlog_packets: u32 = 0,
    backlog_bytes: u32 = 0,
    /// The tin's rate threshold in bytes per second.
    threshold_rate: u64 = 0,
    target_us: u32 = 0,
    interval_us: u32 = 0,
    way_indirect_hits: u32 = 0,
    way_misses: u32 = 0,
    way_collisions: u32 = 0,
    peak_delay_us: u32 = 0,
    avg_delay_us: u32 = 0,
    base_delay_us: u32 = 0,
    sparse_flows: u32 = 0,
    bulk_flows: u32 = 0,
    unresponsive_flows: u32 = 0,
    max_skblen: u32 = 0,
    flow_quantum: u32 = 0,
};

/// The most tins cake has (`CAKE_MAX_TINS`).
pub const cake_max_tins = 8;

/// `TCA_CAKE_STATS` as dumped in `TCA_XSTATS`: the qdisc-wide figures and one
/// `CakeTinStats` per tin. An attribute the kernel did not send stays 0.
pub const CakeStats = struct {
    /// The estimated link capacity in bytes per second.
    capacity_estimate: u64 = 0,
    memory_limit: u32 = 0,
    memory_used: u32 = 0,
    avg_netoff: u32 = 0,
    min_netlen: u32 = 0,
    max_netlen: u32 = 0,
    min_adjlen: u32 = 0,
    max_adjlen: u32 = 0,
    tins: [cake_max_tins]CakeTinStats = @splat(.{}),
    /// How many entries of `tins` are filled.
    tin_count: u8 = 0,

    pub fn tinSlice(c: *const CakeStats) []const CakeTinStats {
        return c.tins[0..c.tin_count];
    }
};

/// What a dump's `TCA_XSTATS` held, by the kind it came from.
pub const Xstats = union(enum) {
    fq_codel: FqCodelXstats,
    fq_codel_class: FqCodelClassXstats,
    htb: HtbXstats,
    hfsc: HfscXstats,
    red: RedXstats,
    codel: CodelXstats,
    cake: CakeStats,
};

fn rdi32(d: []const u8, off: usize) i32 {
    return std.mem.readInt(i32, d[off..][0..4], native_endian);
}

fn parseCakeStats(data: []const u8) codec.Error!CakeStats {
    var c: CakeStats = .{};
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| switch (a.type) {
        TCA_CAKE_STATS.CAPACITY_ESTIMATE64 => if (a.data.len == 8) {
            c.capacity_estimate = rd64(a.data, 0);
        },
        TCA_CAKE_STATS.MEMORY_LIMIT => if (a.data.len == 4) {
            c.memory_limit = rd32(a.data, 0);
        },
        TCA_CAKE_STATS.MEMORY_USED => if (a.data.len == 4) {
            c.memory_used = rd32(a.data, 0);
        },
        TCA_CAKE_STATS.AVG_NETOFF => if (a.data.len == 4) {
            c.avg_netoff = rd32(a.data, 0);
        },
        TCA_CAKE_STATS.MIN_NETLEN => if (a.data.len == 4) {
            c.min_netlen = rd32(a.data, 0);
        },
        TCA_CAKE_STATS.MAX_NETLEN => if (a.data.len == 4) {
            c.max_netlen = rd32(a.data, 0);
        },
        TCA_CAKE_STATS.MIN_ADJLEN => if (a.data.len == 4) {
            c.min_adjlen = rd32(a.data, 0);
        },
        TCA_CAKE_STATS.MAX_ADJLEN => if (a.data.len == 4) {
            c.max_adjlen = rd32(a.data, 0);
        },
        TCA_CAKE_STATS.TIN_STATS => {
            var tit: codec.AttrIterator = .{ .buf = a.data };
            while (try tit.next()) |tin| {
                if (c.tin_count >= cake_max_tins) break;
                c.tins[c.tin_count] = try parseCakeTin(tin.data);
                c.tin_count += 1;
            }
        },
        else => {},
    };
    return c;
}

fn parseCakeTin(data: []const u8) codec.Error!CakeTinStats {
    var t: CakeTinStats = .{};
    const T = TCA_CAKE_TIN_STATS;
    var it: codec.AttrIterator = .{ .buf = data };
    while (try it.next()) |a| {
        const v32: ?u32 = if (a.data.len == 4) rd32(a.data, 0) else null;
        const v64: ?u64 = if (a.data.len == 8) rd64(a.data, 0) else null;
        switch (a.type) {
            T.SENT_PACKETS => t.sent_packets = v32 orelse t.sent_packets,
            T.SENT_BYTES64 => t.sent_bytes = v64 orelse t.sent_bytes,
            T.DROPPED_PACKETS => t.dropped_packets = v32 orelse t.dropped_packets,
            T.DROPPED_BYTES64 => t.dropped_bytes = v64 orelse t.dropped_bytes,
            T.ACKS_DROPPED_PACKETS => t.acks_dropped_packets = v32 orelse t.acks_dropped_packets,
            T.ACKS_DROPPED_BYTES64 => t.acks_dropped_bytes = v64 orelse t.acks_dropped_bytes,
            T.ECN_MARKED_PACKETS => t.ecn_marked_packets = v32 orelse t.ecn_marked_packets,
            T.ECN_MARKED_BYTES64 => t.ecn_marked_bytes = v64 orelse t.ecn_marked_bytes,
            T.BACKLOG_PACKETS => t.backlog_packets = v32 orelse t.backlog_packets,
            T.BACKLOG_BYTES => t.backlog_bytes = v32 orelse t.backlog_bytes,
            T.THRESHOLD_RATE64 => t.threshold_rate = v64 orelse t.threshold_rate,
            T.TARGET_US => t.target_us = v32 orelse t.target_us,
            T.INTERVAL_US => t.interval_us = v32 orelse t.interval_us,
            T.WAY_INDIRECT_HITS => t.way_indirect_hits = v32 orelse t.way_indirect_hits,
            T.WAY_MISSES => t.way_misses = v32 orelse t.way_misses,
            T.WAY_COLLISIONS => t.way_collisions = v32 orelse t.way_collisions,
            T.PEAK_DELAY_US => t.peak_delay_us = v32 orelse t.peak_delay_us,
            T.AVG_DELAY_US => t.avg_delay_us = v32 orelse t.avg_delay_us,
            T.BASE_DELAY_US => t.base_delay_us = v32 orelse t.base_delay_us,
            T.SPARSE_FLOWS => t.sparse_flows = v32 orelse t.sparse_flows,
            T.BULK_FLOWS => t.bulk_flows = v32 orelse t.bulk_flows,
            T.UNRESPONSIVE_FLOWS => t.unresponsive_flows = v32 orelse t.unresponsive_flows,
            T.MAX_SKBLEN => t.max_skblen = v32 orelse t.max_skblen,
            T.FLOW_QUANTUM => t.flow_quantum = v32 orelse t.flow_quantum,
            else => {},
        }
    }
    return t;
}

/// Decode a `TCA_XSTATS` payload by the qdisc or class kind it came from;
/// null for a kind this module has no struct for or a payload shorter than
/// the kernel's. `is_class` picks the class layout where the kind has both
/// (`fq_codel`).
pub fn parseXstats(kind_name: []const u8, is_class: bool, data: []const u8) codec.Error!?Xstats {
    if (std.mem.eql(u8, kind_name, kind_htb)) {
        if (data.len < 20) return null;
        return .{ .htb = .{
            .lends = rd32(data, 0),
            .borrows = rd32(data, 4),
            .giants = rd32(data, 8),
            .tokens = rdi32(data, 12),
            .ctokens = rdi32(data, 16),
        } };
    } else if (std.mem.eql(u8, kind_name, kind_hfsc)) {
        if (data.len < 24) return null;
        return .{ .hfsc = .{ .work = rd64(data, 0), .rtwork = rd64(data, 8), .period = rd32(data, 16), .level = rd32(data, 20) } };
    } else if (std.mem.eql(u8, kind_name, kind_red)) {
        if (data.len < 16) return null;
        return .{ .red = .{ .early = rd32(data, 0), .pdrop = rd32(data, 4), .other = rd32(data, 8), .marked = rd32(data, 12) } };
    } else if (std.mem.eql(u8, kind_name, kind_codel)) {
        if (data.len < 36) return null;
        return .{ .codel = .{
            .maxpacket = rd32(data, 0),
            .count = rd32(data, 4),
            .lastcount = rd32(data, 8),
            .ldelay = rd32(data, 12),
            .drop_next = rdi32(data, 16),
            .drop_overlimit = rd32(data, 20),
            .ecn_mark = rd32(data, 24),
            .dropping = rd32(data, 28),
            .ce_mark = rd32(data, 32),
        } };
    } else if (std.mem.eql(u8, kind_name, kind_fq_codel)) {
        if (is_class) {
            if (data.len < 28 or rd32(data, 0) != fq_codel_xstats_class) return null;
            return .{ .fq_codel_class = .{
                .deficit = rdi32(data, 4),
                .ldelay = rd32(data, 8),
                .count = rd32(data, 12),
                .lastcount = rd32(data, 16),
                .dropping = rd32(data, 20),
                .drop_next = rdi32(data, 24),
            } };
        }
        const q = parseFqCodelXstats(data) orelse return null;
        return .{ .fq_codel = q };
    } else if (std.mem.eql(u8, kind_name, kind_cake)) {
        return .{ .cake = try parseCakeStats(data) };
    }
    return null;
}

/// The `TCA_STATS_APP` payload of a `TCA_STATS2` nest: the kind's own
/// statistics, as it dumps them there.
fn appStats(stats2: ?[]const u8) codec.Error!?[]const u8 {
    const d = stats2 orelse return null;
    var it: codec.AttrIterator = .{ .buf = d };
    while (try it.next()) |a| {
        if (a.type == TCA_STATS2.APP) return a.data;
    }
    return null;
}

fn parseFqCodelXstats(data: []const u8) ?FqCodelXstats {
    if (data.len < fq_codel_xstats_len or rd32(data, 0) != fq_codel_xstats_qdisc) return null;
    return .{
        .maxpacket = rd32(data, 4),
        .drop_overlimit = rd32(data, 8),
        .ecn_mark = rd32(data, 12),
        .new_flow_count = rd32(data, 16),
        .new_flows_len = rd32(data, 20),
        .old_flows_len = rd32(data, 24),
        .ce_mark = rd32(data, 28),
        .memory_usage = rd32(data, 32),
        .drop_overmemory = rd32(data, 36),
    };
}

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
    prio: ?PrioWire = null,
    /// `pfifo` and `bfifo` (told apart by `kind()`).
    fifo: ?FifoWire = null,
    sfq: ?SfqWire = null,
    codel: ?CodelWire = null,
    fq: ?FqWire = null,
    hfsc: ?HfscWire = null,
    red: ?RedWire = null,
    /// `TCA_STAB`, when the qdisc has a size table.
    stab: ?StabWire = null,
    /// Counters (`tc -s`); null when the kernel sent none (API addition).
    stats: ?Stats = null,
    /// `TCA_XSTATS` of an `fq_codel` qdisc. Other kinds' private statistics
    /// are not decoded (their raw bytes are not kept either).
    fq_codel_xstats: ?FqCodelXstats = null,
    /// `TCA_XSTATS` decoded for whichever kind this is (`htb`, `hfsc`, `red`,
    /// `codel`, `fq_codel`, `cake`); null when none came or the kind has no
    /// decoder. `fq_codel_xstats` stays for the fq_codel qdisc.
    xstats: ?Xstats = null,

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
    /// Service curves, when `kind() == "hfsc"`.
    hfsc: ?HfscClassWire = null,
    /// `TCA_XSTATS` for an htb, hfsc or fq_codel class (see `Qdisc.xstats`).
    xstats: ?Xstats = null,
    /// Counters (`tc -s`); null when the kernel sent none (API addition).
    stats: ?Stats = null,

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
    var stats2: ?[]const u8 = null;
    var legacy: ?[]const u8 = null;
    var xstats: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = payload[tcmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        TCA.KIND => try copyKind(&q.kind_buf, &q.kind_len, a.asString()),
        TCA.OPTIONS => options_data = a.data,
        TCA.STATS2 => stats2 = a.data,
        TCA.STATS => legacy = a.data,
        TCA.XSTATS => xstats = a.data,
        TCA.STAB => q.stab = try parseStab(a.data),
        else => {},
    };
    q.stats = try pickStats(stats2, legacy);
    // Most kinds also send the legacy `TCA_XSTATS`; cake nests its figures
    // only in `TCA_STATS2`'s `TCA_STATS_APP`.
    if (xstats orelse try appStats(stats2)) |x| {
        if (std.mem.eql(u8, q.kind(), kind_fq_codel)) q.fq_codel_xstats = parseFqCodelXstats(x);
        q.xstats = try parseXstats(q.kind(), false, x);
    }
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
        } else if (std.mem.eql(u8, k, kind_prio)) {
            q.prio = parsePrioOptions(opt);
        } else if (std.mem.eql(u8, k, kind_pfifo) or std.mem.eql(u8, k, kind_bfifo) or
            std.mem.eql(u8, k, kind_pfifo_head_drop))
        {
            q.fifo = parseFifoOptions(opt);
        } else if (std.mem.eql(u8, k, kind_pfifo_fast)) {
            // The kernel dumps pfifo_fast's bands and priomap as a prio qopt.
            q.prio = parsePrioOptions(opt);
        } else if (std.mem.eql(u8, k, kind_sfq)) {
            q.sfq = parseSfqOptions(opt);
        } else if (std.mem.eql(u8, k, kind_codel)) {
            q.codel = try parseCodelOptions(opt);
        } else if (std.mem.eql(u8, k, kind_fq)) {
            q.fq = try parseFqOptions(opt);
        } else if (std.mem.eql(u8, k, kind_hfsc)) {
            q.hfsc = parseHfscOptions(opt);
        } else if (std.mem.eql(u8, k, kind_red)) {
            q.red = try parseRedOptions(opt);
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
    var stats2: ?[]const u8 = null;
    var legacy: ?[]const u8 = null;
    var xstats: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = payload[tcmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        TCA.KIND => try copyKind(&c.kind_buf, &c.kind_len, a.asString()),
        TCA.OPTIONS => options_data = a.data,
        TCA.STATS2 => stats2 = a.data,
        TCA.STATS => legacy = a.data,
        TCA.XSTATS => xstats = a.data,
        else => {},
    };
    c.stats = try pickStats(stats2, legacy);
    if (xstats orelse try appStats(stats2)) |x| c.xstats = try parseXstats(c.kind(), true, x);
    if (options_data) |opt| {
        if (std.mem.eql(u8, c.kind(), kind_htb)) {
            c.htb = try parseHtbClassOptions(opt);
        } else if (std.mem.eql(u8, c.kind(), kind_hfsc)) {
            c.hfsc = try parseHfscClassOptions(opt);
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

const appendAttrU64 = codec.appendAttrU64;

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
    try testing.expectEqual(@as(u32, 1), @backingInt(CakeDiffservMode.diffserv4));
    try testing.expectEqual(@as(u32, 5), @backingInt(CakeFlowMode.dual_srchost));
    try testing.expectEqual(@as(u32, 2), @backingInt(CakeAtmMode.ptm));
    try testing.expectEqual(@as(u32, 1), @backingInt(CakeAckFilter.filter));
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

test "appendHtbClassOptions rejects cell_log/ccell_log >= 32 instead of panicking (F2)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try testing.expectError(error.InvalidCellLog, appendHtbClassOptions(
        .{ .rate = 125_000, .cell_log = 32 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    try testing.expectError(error.InvalidCellLog, appendHtbClassOptions(
        .{ .rate = 125_000, .ccell_log = 200 },
        gpa,
        &list,
        ratespec.golden_psched,
    ));
    // Positive control: the field this guards must still work untouched.
    try appendHtbClassOptions(.{ .rate = 125_000, .cell_log = 3 }, gpa, &list, ratespec.golden_psched);
}

test "parseHtbClassOptions rejects a TCA_HTB_PARMS attribute shorter than tc_htb_opt_len (F3)" {
    // Wave-3 audit's F3: this bound (root.zig-era line "qdisc.zig:546") was
    // named as untested fault-injection surface — the fuzz corpus that was
    // fixed exercises this parser with real-shaped payloads, but
    // "never crashes" is not the same claim as "rejects a truncated PARMS
    // attribute" (a short attribute here doesn't panic, it silently reads
    // fewer fields than the wire format promises — a correctness bug, not a
    // memory-safety one, and crash-only fuzzing cannot see it). Pinned
    // directly instead.
    const gpa = testing.allocator;

    var short_list: std.ArrayList(u8) = .empty;
    defer short_list.deinit(gpa);
    var short: [tc_htb_opt_len - 1]u8 = @splat(0);
    try appendAttr(gpa, &short_list, TCA_HTB.PARMS, &short);
    try testing.expectError(error.BadLength, parseHtbClassOptions(short_list.items));

    // Positive control: exactly tc_htb_opt_len bytes must still parse.
    var ok_list: std.ArrayList(u8) = .empty;
    defer ok_list.deinit(gpa);
    var ok: [tc_htb_opt_len]u8 = @splat(0);
    try appendAttr(gpa, &ok_list, TCA_HTB.PARMS, &ok);
    _ = try parseHtbClassOptions(ok_list.items);
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
    try testing.expectError(error.InvalidCellLog, appendTbfOptions(
        .{ .rate = 1, .burst = 1, .limit = 1, .cell_log = 32 },
        gpa,
        &list,
        ps,
    ));
    try testing.expectError(error.InvalidCellLog, appendTbfOptions(
        .{ .rate = 1, .burst = 1, .limit = 1, .pcell_log = 40 },
        gpa,
        &list,
        ps,
    ));
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "kind_max is the delivered 16-byte TCA_KIND budget, and the boundary is exact" {
    // 16 is the shipped limit (`kind_max` above), pinned literally so a
    // change to the constant is caught here rather than read off the symbol
    // it is checked against. The longest real qdisc kind on this host's
    // iproute2/kernel is "pfifo_head_drop" (15 bytes), one under the limit;
    // `codec.asString` trims the trailing NUL before this is reached, so the
    // margin really is one byte.
    try testing.expectEqual(@as(usize, 16), kind_max);

    var buf: [kind_max]u8 = undefined;
    var len: u8 = 0;

    // Exactly at the boundary: accepted.
    const at_boundary = "0123456789abcdef"; // 16 bytes
    try testing.expectEqual(@as(usize, 16), at_boundary.len);
    try copyKind(&buf, &len, at_boundary);
    try testing.expectEqualStrings(at_boundary, buf[0..len]);

    // One byte over: rejected, not truncated.
    const over_boundary = "0123456789abcdefg"; // 17 bytes
    try testing.expectEqual(@as(usize, 17), over_boundary.len);
    try testing.expectError(error.BadLength, copyKind(&buf, &len, over_boundary));

    // The real-world longest kind name still fits comfortably.
    try copyKind(&buf, &len, "pfifo_head_drop");
    try testing.expectEqualStrings("pfifo_head_drop", buf[0..len]);
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
    try testing.expectEqualStrings("ingress", (QdiscSpec{ .ingress = .{} }).kind());
    try testing.expectEqualStrings("clsact", (QdiscSpec{ .clsact = .{} }).kind());
    // Only mq, ingress and clsact withhold the options nest.
    try testing.expect(!(QdiscSpec{ .mq = .{} }).carriesOptions());
    try testing.expect(!(QdiscSpec{ .ingress = .{} }).carriesOptions());
    try testing.expect(!(QdiscSpec{ .clsact = .{} }).carriesOptions());
    try testing.expect((QdiscSpec{ .cake = .{} }).carriesOptions());
    try testing.expect((QdiscSpec{ .fq_codel = .{} }).carriesOptions());
}

/// `TCA_OPTIONS` bodies and whole `struct tcmsg` payloads for
/// `fuzzParseOptions`, in the format `Smith.slice` reads (see `testkit.fuzz`):
/// a little-endian u32 length, then the frame.
///
/// ⭐ Built at run time by this file's own encoders rather than quoted as hex.
/// Every tc option is a netlink TLV whose `nla_len`/`nla_type` and whose
/// scalars are in HOST byte order, so a hex corpus would be a little-endian
/// one and the counts pinned below would silently be false on a big-endian
/// target instead of failing there.
///
/// ⛔ The buffer had to grow with it. An htb *class* options nest carries two
/// 1 KiB rate tables (`RTAB`/`CTAB`), so the shortest complete one this module
/// can emit is over 2 KiB against the harness's old 256-octet buffer — and a
/// seed longer than the buffer is not a big seed, `Smith.slice` reads it back
/// as the EMPTY one. The one option payload with a loop long enough to matter
/// could never have passed through this module's own harness.
const OptionsCorpus = struct {
    scratch: [16384]u8 = undefined,
    store: [16384]u8 = undefined,
    used: usize = 0,
    entries: [19][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *OptionsCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    /// A `struct tcmsg` fixed header, which is what `parseQdisc` and
    /// `parseClass` take in front of the attribute list. Written here rather
    /// than borrowed from `message.appendTcmsg` because `message.zig` imports
    /// this file, and the dependency only goes that way.
    fn tcmsg(
        gpa: std.mem.Allocator,
        list: *std.ArrayList(u8),
        ifindex: u32,
        h: Handle,
        parent: Handle,
    ) !void {
        var hdr: [tcmsg_len]u8 = @splat(0);
        std.mem.writeInt(i32, hdr[4..8], @bitCast(ifindex), native_endian);
        std.mem.writeInt(u32, hdr[8..12], h.raw, native_endian);
        std.mem.writeInt(u32, hdr[12..16], parent.raw, native_endian);
        try codec.appendPadded(gpa, list, &hdr);
    }

    fn build(self: *OptionsCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();
        const ps = ratespec.golden_psched;

        // ── option bodies, one per kind ────────────────────────────────────
        // netem with every extended attribute the parser knows: CORR,
        // REORDER, CORRUPT, RATE, LATENCY64, JITTER64.
        var netem: std.ArrayList(u8) = .empty;
        try appendNetemOptions(.{
            .limit = 2000,
            .delay_ns = 100_000_000,
            .jitter_ns = 10_000_000,
            .delay_correlation_pct = 25,
            .loss_pct = 1.5,
            .loss_correlation_pct = 10,
            .duplicate_pct = 0.5,
            .duplicate_correlation_pct = 5,
            .reorder_pct = 2,
            .reorder_correlation_pct = 50,
            .reorder_gap = 5,
            .corrupt_pct = 0.1,
            .corrupt_correlation_pct = 3,
            .rate_bytes_per_sec = 125_000,
        }, gpa, &netem);
        self.push(netem.items);

        // htb at the qdisc level: INIT + DIRECT_QLEN + the OFFLOAD flag.
        var htb: std.ArrayList(u8) = .empty;
        try appendHtbOptions(.{
            .rate2quantum = 10,
            .defcls = 0x10,
            .direct_qlen = 1000,
            .offload = true,
        }, gpa, &htb);
        self.push(htb.items);

        // htb at the class level: the two 1 KiB rate tables and the
        // RATE64/CEIL64 companions a >= 2^32 rate forces.
        var htb_class: std.ArrayList(u8) = .empty;
        try appendHtbClassOptions(.{
            .rate = 5_000_000_000,
            .ceil = 10_000_000_000,
            .prio = 3,
            .quantum = 3000,
        }, gpa, &htb_class, ps);
        self.push(htb_class.items);

        // tbf with a peak bucket: two ratespecs, BURST and PBURST.
        var tbf: std.ArrayList(u8) = .empty;
        try appendTbfOptions(.{
            .rate = 1_250_000,
            .burst = 10240,
            .latency_us = 50_000,
            .peakrate = 2_500_000,
            .mtu = 1500,
        }, gpa, &tbf, ps);
        self.push(tbf.items);

        // fq_codel with every knob present.
        var fq: std.ArrayList(u8) = .empty;
        try appendFqCodelOptions(.{
            .limit = 10240,
            .flows = 1024,
            .quantum = 1514,
            .interval_us = 100_000,
            .target_us = 5000,
            .ecn = true,
            .ce_threshold_us = 1000,
            .memory_limit = 32 << 20,
            .drop_batch = 64,
        }, gpa, &fq);
        self.push(fq.items);

        // cake with every knob present — the widest attribute list here.
        var cake: std.ArrayList(u8) = .empty;
        try appendCakeOptions(.{
            .bandwidth = 12_500_000,
            .diffserv = .diffserv4,
            .atm = .ptm,
            .flow_mode = .triple_isolate,
            .overhead = 18,
            .mpu = 64,
            .rtt_us = 100_000,
            .target_us = 5000,
            .autorate_ingress = false,
            .memlimit = 4 << 20,
            .fwmark = 0xff,
            .nat = true,
            .wash = true,
            .split_gso = false,
            .ack_filter = .aggressive,
            .ingress = false,
        }, gpa, &cake);
        self.push(cake.items);

        // ── whole tcmsg payloads, which is what a dump hands `parseQdisc` ──
        var q_netem: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &q_netem, 2, Handle.init(1, 0), Handle.root);
        try codec.appendAttrString(gpa, &q_netem, TCA.KIND, kind_netem);
        try codec.appendAttr(gpa, &q_netem, TCA.OPTIONS, netem.items);
        self.push(q_netem.items);

        var q_cake: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &q_cake, 2, Handle.init(0x8001, 0), Handle.root);
        try codec.appendAttrString(gpa, &q_cake, TCA.KIND, kind_cake);
        try codec.appendAttr(gpa, &q_cake, TCA.OPTIONS, cake.items);
        self.push(q_cake.items);

        // An RTM_NEWTCLASS payload: the same shape, read by `parseClass`.
        var c_htb: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &c_htb, 2, Handle.init(1, 0x10), Handle.init(1, 0));
        try codec.appendAttrString(gpa, &c_htb, TCA.KIND, kind_htb);
        try codec.appendAttr(gpa, &c_htb, TCA.OPTIONS, htb_class.items);
        self.push(c_htb.items);

        // A qdisc naming a kind this module does not model: the KIND is
        // copied, the OPTIONS nest is left unparsed.
        var q_sfq: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &q_sfq, 3, Handle.init(2, 0), Handle.root);
        try codec.appendAttrString(gpa, &q_sfq, TCA.KIND, "sfq");
        try codec.appendAttr(gpa, &q_sfq, TCA.OPTIONS, &[_]u8{ 1, 2, 3, 4 });
        self.push(q_sfq.items);

        // ── attributes that arrive with the WRONG length ───────────────────
        // ⭐ These are the seeds the mutation testing asked for. Every
        // `if (a.data.len == N)` in the five option parsers is a bound that a
        // well-formed capture can never exercise: weaken it to `>= 4` and the
        // read runs off the end of `a.data`. Seven such mutations survived a
        // green suite before this corpus existed, three of them writing out of
        // bounds, because the harness handed every parser an empty slice and
        // no test ever put a short attribute in front of one.
        var netem_short: std.ArrayList(u8) = .empty;
        try netem_short.appendSlice(gpa, &(@as([tc_netem_qopt_len]u8, @splat(0))));
        try codec.appendAttr(gpa, &netem_short, TCA_NETEM.CORR, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &netem_short, TCA_NETEM.REORDER, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &netem_short, TCA_NETEM.CORRUPT, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &netem_short, TCA_NETEM.RATE, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &netem_short, TCA_NETEM.LATENCY64, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &netem_short, TCA_NETEM.JITTER64, &@as([4]u8, @splat(0)));
        self.push(netem_short.items);

        // htb, both levels. RATE64/CEIL64 come before the short PARMS, which
        // ends the class walk with `BadLength`.
        var htb_short: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &htb_short, TCA_HTB.INIT, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &htb_short, TCA_HTB.DIRECT_QLEN, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &htb_short, TCA_HTB.RATE64, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &htb_short, TCA_HTB.CEIL64, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &htb_short, TCA_HTB.PARMS, &@as([4]u8, @splat(0)));
        self.push(htb_short.items);

        var tbf_short: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &tbf_short, TCA_TBF.RATE64, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &tbf_short, TCA_TBF.PRATE64, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &tbf_short, TCA_TBF.BURST, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &tbf_short, TCA_TBF.PBURST, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &tbf_short, TCA_TBF.PARMS, &@as([4]u8, @splat(0)));
        self.push(tbf_short.items);

        var cake_short: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &cake_short, TCA_CAKE.BASE_RATE64, &@as([4]u8, @splat(0)));
        try codec.appendAttr(gpa, &cake_short, TCA_CAKE.OVERHEAD, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &cake_short, TCA_CAKE.DIFFSERV_MODE, &@as([2]u8, @splat(0)));
        try codec.appendAttr(gpa, &cake_short, TCA_CAKE.MPU, &@as([8]u8, @splat(0)));
        try codec.appendAttr(gpa, &cake_short, TCA_CAKE.RAW, &.{});
        self.push(cake_short.items);

        // ── the refusals ───────────────────────────────────────────────────
        // A payload one octet short of `struct tcmsg`.
        self.push(&(@as([tcmsg_len - 1]u8, @splat(0))));
        // A KIND string one octet past `kind_max`, which `copyKind` refuses.
        var long_kind: std.ArrayList(u8) = .empty;
        try tcmsg(gpa, &long_kind, 2, Handle.unspec, Handle.root);
        try codec.appendAttrString(gpa, &long_kind, TCA.KIND, "0123456789abcdefg");
        self.push(long_kind.items);
        // An attribute header declaring 0x40 octets over a 2-octet buffer.
        self.push(&[_]u8{ 0x40, 0x00 });
        // A netem qopt one octet short of `tc_netem_qopt_len`.
        self.push(&(@as([tc_netem_qopt_len - 1]u8, @splat(0))));
        // A complete netem qopt followed by a TLV running off the end.
        self.push(&(@as([tc_netem_qopt_len]u8, @splat(0)) ++ [_]u8{ 0x40, 0x00, 0x03, 0x00, 0x01 }));

        return self.entries[0..self.n];
    }
};

/// How many of a `*Wire` struct's optional fields came back present.
///
/// ⭐ This is the **second number** every corpus guard in this module pins, and
/// it exists because the first one cannot do the job alone: an empty attribute
/// list is a legal `TCA_OPTIONS` body for five of the eight parsers here, so
/// they succeed on the empty slice a collapsed harness hands them and return a
/// struct of all-null. An acceptance count therefore reads as full marks while
/// nothing walks a single TLV; a count of fields that only exist after the walk
/// ran cannot. `pub` because `filter.zig` and `action.zig` pin the same number.
pub fn optionalsSet(v: anytype) usize {
    var n: usize = 0;
    inline for (@typeInfo(@TypeOf(v)).@"struct".field_names, @typeInfo(@TypeOf(v)).@"struct".field_types) |f_name, f_type| {
        if (@typeInfo(f_type) == .optional) {
            if (@field(v, f_name) != null) n += 1;
        }
    }
    return n;
}

const fz = @import("fuzz_test.zig");
const OptionsMark = fz.Marker(enum { netem, shaper, optionals, qdisc, class, refused });

test "fuzz: option parsers never crash on arbitrary payloads" {
    var corpus: OptionsCorpus = .{};
    try testing.fuzz({}, fuzzParseOptionsSmith, .{ .corpus = try corpus.build() });
}

test "fuzz driver: TC_FUZZ (options)" {
    try fz.fuzz_driver.run(fuzzParseOptions, .{ .prefix = "TC_FUZZ", .name = "tc-options" });
}

test "fuzz harness: options, 500 seeds, reaches every outcome" {
    try OptionsMark.reach(fuzzParseOptions, "tc-options", 500);
}

fn fuzzParseOptionsSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzParseOptions(std.testing.Smith, smith, testing.allocator);
}

fn fuzzParseOptions(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var corpus: OptionsCorpus = .{};
    const entries = corpus.build() catch return;
    // ⛔ 4096, not 256. See `OptionsCorpus`: an htb class options nest is over
    // 2 KiB of rate tables, and a seed longer than the buffer reads back EMPTY.
    var raw: [4096]u8 = undefined;
    // ⚠ One `src.slice` call, never `src.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and all eight parsers were handed an EMPTY
    // slice with the payload sitting unread in `raw`.
    //
    // ⛔ Measured over the corpus above: **0 of 19 seeds non-empty,
    // 0 netem options parsed, 0 qdisc kinds read and 0 optional cake/fq_codel/
    // tbf/htb fields decoded before; 19 of 19 non-empty, 8 netem, 8 kinds and
    // 65 optionals after.** And **5 of the 8 parsers *succeeded* on that empty
    // slice** — an empty attribute list is a legal options body — so an
    // acceptance count said the harness was healthy while it walked nothing.
    const len: usize = fz.drawInput(S, src, &raw, entries);
    const buf = raw[0..len];
    if (parseNetemOptions(buf)) |_| OptionsMark.mark(.netem) else |_| OptionsMark.mark(.refused);
    if (parseHtbOptions(buf)) |w| {
        OptionsMark.mark(.shaper);
        if (optionalsSet(w) != 0) OptionsMark.mark(.optionals);
    } else |_| {}
    if (parseHtbClassOptions(buf)) |_| {} else |_| {}
    if (parseTbfOptions(buf)) |w| {
        OptionsMark.mark(.shaper);
        if (optionalsSet(w) != 0) OptionsMark.mark(.optionals);
    } else |_| {}
    if (parseFqCodelOptions(buf)) |w| {
        if (optionalsSet(w) != 0) OptionsMark.mark(.optionals);
    } else |_| {}
    if (parseCakeOptions(buf)) |w| {
        if (optionalsSet(w) != 0) OptionsMark.mark(.optionals);
    } else |_| {}
    if (parseQdisc(buf)) |q| {
        std.mem.doNotOptimizeAway(q.kind().len);
        if (q.kind().len != 0) OptionsMark.mark(.qdisc);
    } else |_| {}
    if (parseClass(buf)) |c| {
        std.mem.doNotOptimizeAway(c.kind().len);
        if (c.kind().len != 0) OptionsMark.mark(.class);
    } else |_| {}
}

test "corpus: every option seed reaches the parsers, and the decoded counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently.
    //
    // ⛔ The other three numbers are the ones an empty payload cannot produce.
    // "Parsers that succeeded" is not among them: `parseHtbOptions`,
    // `parseHtbClassOptions`, `parseTbfOptions`, `parseFqCodelOptions`,
    // `parseCakeOptions` and `parseClass`'s attribute walk all accept an empty
    // attribute list, so a collapsed harness scores six accepts a round while
    // never entering a TLV loop. `netem` needs 24 octets of fixed header,
    // `kinds` needs a KIND attribute actually copied out, and `optionals`
    // counts fields that only exist if the walk ran.
    var corpus: OptionsCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var netem: usize = 0;
    var kinds: usize = 0;
    var optionals: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [4096]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const buf = raw[0..len];
        if (parseNetemOptions(buf)) |_| netem += 1 else |_| {}
        if (parseFqCodelOptions(buf)) |w| optionals += optionalsSet(w) else |_| {}
        if (parseCakeOptions(buf)) |w| optionals += optionalsSet(w) else |_| {}
        if (parseTbfOptions(buf)) |w| optionals += optionalsSet(w) else |_| {}
        if (parseHtbOptions(buf)) |w| optionals += optionalsSet(w) else |_| {}
        if (parseQdisc(buf)) |q| {
            if (q.kind().len != 0) kinds += 1;
        } else |_| {}
        if (parseClass(buf)) |c| {
            if (c.kind().len != 0) kinds += 1;
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 8), netem);
    try testing.expectEqual(@as(usize, 8), kinds);
    try testing.expectEqual(@as(usize, 65), optionals);
}

// ── statistics decoding ─────────────────────────────────────────────────────

fn statsFixture(gpa: std.mem.Allocator, list: *std.ArrayList(u8), kind_s: []const u8) !void {
    var hdr: [tcmsg_len]u8 = @splat(0);
    std.mem.writeInt(i32, hdr[4..8], 7, native_endian);
    try codec.appendPadded(gpa, list, &hdr);
    try codec.appendAttrString(gpa, list, TCA.KIND, kind_s);
}

fn le32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, native_endian);
}

fn le64(buf: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], v, native_endian);
}

fn stats2Nest(gpa: std.mem.Allocator, pkt64: bool, truncate: ?u16) !std.ArrayList(u8) {
    var n: std.ArrayList(u8) = .empty;
    var basic: [16]u8 = @splat(0);
    le64(&basic, 0, 123_456_789_012);
    le32(&basic, 8, 1000);
    try codec.appendAttr(gpa, &n, TCA_STATS2.BASIC, if (truncate == TCA_STATS2.BASIC) basic[0..11] else &basic);
    var rate: [8]u8 = @splat(0);
    le32(&rate, 0, 5);
    le32(&rate, 4, 6);
    try codec.appendAttr(gpa, &n, TCA_STATS2.RATE_EST, &rate);
    var queue: [20]u8 = @splat(0);
    for (0..5) |i| le32(&queue, i * 4, @intCast(10 + i)); // qlen..overlimits
    try codec.appendAttr(gpa, &n, TCA_STATS2.QUEUE, if (truncate == TCA_STATS2.QUEUE) queue[0..19] else &queue);
    if (pkt64) {
        var p: [8]u8 = undefined;
        le64(&p, 0, 5_000_000_000);
        try codec.appendAttr(gpa, &n, TCA_STATS2.PKT64, &p);
    }
    return n;
}

test "stats: TCA_STATS2 full, PKT64 overrides the u32 packet count" {
    const gpa = testing.allocator;
    var n = try stats2Nest(gpa, true, null);
    defer n.deinit(gpa);
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try statsFixture(gpa, &m, "htb");
    try codec.appendAttr(gpa, &m, TCA.STATS2, n.items);
    const q = try parseQdisc(m.items);
    const s = q.stats.?;
    try testing.expectEqual(@as(u64, 123_456_789_012), s.bytes);
    try testing.expectEqual(@as(u64, 5_000_000_000), s.packets);
    try testing.expectEqual(@as(u32, 10), s.qlen);
    try testing.expectEqual(@as(u32, 11), s.backlog);
    try testing.expectEqual(@as(u32, 12), s.drops);
    try testing.expectEqual(@as(u32, 13), s.requeues);
    try testing.expectEqual(@as(u32, 14), s.overlimits);
    try testing.expectEqual(@as(u64, 5), s.bps);
    try testing.expectEqual(@as(u64, 6), s.pps);
    const c = try parseClass(m.items);
    try testing.expectEqual(@as(u64, 123_456_789_012), c.stats.?.bytes);
}

test "stats: TCA_STATS2 without PKT64 keeps the u32 packet count" {
    const gpa = testing.allocator;
    var n = try stats2Nest(gpa, false, null);
    defer n.deinit(gpa);
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try statsFixture(gpa, &m, "noqueue");
    try codec.appendAttr(gpa, &m, TCA.STATS2, n.items);
    try testing.expectEqual(@as(u64, 1000), (try parseQdisc(m.items)).stats.?.packets);
}

test "stats: legacy TCA_STATS is the fallback, STATS2 wins when both are present" {
    const gpa = testing.allocator;
    var legacy: [40]u8 = @splat(0);
    le64(&legacy, 0, 777);
    le32(&legacy, 8, 7);
    le32(&legacy, 12, 3); // drops
    le32(&legacy, 16, 4); // overlimits
    le32(&legacy, 20, 8); // bps
    le32(&legacy, 24, 9); // pps
    le32(&legacy, 28, 1); // qlen
    le32(&legacy, 32, 2); // backlog
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try statsFixture(gpa, &m, "pfifo");
    try codec.appendAttr(gpa, &m, TCA.STATS, &legacy);
    const s = (try parseQdisc(m.items)).stats.?;
    try testing.expectEqual(@as(u64, 777), s.bytes);
    try testing.expectEqual(@as(u64, 7), s.packets);
    try testing.expectEqual(@as(u32, 3), s.drops);
    try testing.expectEqual(@as(u32, 4), s.overlimits);
    try testing.expectEqual(@as(u64, 8), s.bps);
    try testing.expectEqual(@as(u64, 9), s.pps);
    try testing.expectEqual(@as(u32, 1), s.qlen);
    try testing.expectEqual(@as(u32, 2), s.backlog);
    try testing.expectEqual(@as(u32, 0), s.requeues);

    var n = try stats2Nest(gpa, false, null);
    defer n.deinit(gpa);
    try codec.appendAttr(gpa, &m, TCA.STATS2, n.items);
    try testing.expectEqual(@as(u64, 123_456_789_012), (try parseQdisc(m.items)).stats.?.bytes);
}

test "stats: none sent -> null; short or empty attributes -> null or partial, never an error" {
    const gpa = testing.allocator;
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try statsFixture(gpa, &m, "noqueue");
    try testing.expect((try parseQdisc(m.items)).stats == null);
    try testing.expect((try parseClass(m.items)).stats == null);

    // Truncated BASIC: the queue half still decodes, bytes stay 0.
    var n = try stats2Nest(gpa, false, TCA_STATS2.BASIC);
    defer n.deinit(gpa);
    var m2: std.ArrayList(u8) = .empty;
    defer m2.deinit(gpa);
    try statsFixture(gpa, &m2, "htb");
    try codec.appendAttr(gpa, &m2, TCA.STATS2, n.items);
    const s = (try parseQdisc(m2.items)).stats.?;
    try testing.expectEqual(@as(u64, 0), s.bytes);
    try testing.expectEqual(@as(u32, 12), s.drops);

    // Truncated QUEUE: basic decodes, queue counters stay 0.
    var n3 = try stats2Nest(gpa, false, TCA_STATS2.QUEUE);
    defer n3.deinit(gpa);
    var m3: std.ArrayList(u8) = .empty;
    defer m3.deinit(gpa);
    try statsFixture(gpa, &m3, "htb");
    try codec.appendAttr(gpa, &m3, TCA.STATS2, n3.items);
    const s3 = (try parseQdisc(m3.items)).stats.?;
    try testing.expectEqual(@as(u64, 123_456_789_012), s3.bytes);
    try testing.expectEqual(@as(u32, 0), s3.drops);

    // Only truncated parts, or an empty nest, or a short legacy struct -> null.
    var only: std.ArrayList(u8) = .empty;
    defer only.deinit(gpa);
    try codec.appendAttr(gpa, &only, TCA_STATS2.BASIC, &@as([11]u8, @splat(1)));
    try codec.appendAttr(gpa, &only, TCA_STATS2.QUEUE, &@as([19]u8, @splat(1)));
    var m4: std.ArrayList(u8) = .empty;
    defer m4.deinit(gpa);
    try statsFixture(gpa, &m4, "htb");
    try codec.appendAttr(gpa, &m4, TCA.STATS2, only.items);
    try codec.appendAttr(gpa, &m4, TCA.STATS, &@as([35]u8, @splat(1)));
    try testing.expect((try parseQdisc(m4.items)).stats == null);
    // A malformed nest (attr header claims more than is there) is an error, not a panic.
    var m5: std.ArrayList(u8) = .empty;
    defer m5.deinit(gpa);
    try statsFixture(gpa, &m5, "htb");
    try codec.appendAttr(gpa, &m5, TCA.STATS2, &[_]u8{ 0xff, 0, 1, 0 });
    try testing.expectError(error.Truncated, parseQdisc(m5.items));
}

test "stats: fq_codel TCA_XSTATS (qdisc half) decodes, a short or class-typed one is ignored" {
    const gpa = testing.allocator;
    var x: [40]u8 = @splat(0);
    for (1..10) |i| le32(&x, i * 4, @intCast(i * 100));
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try statsFixture(gpa, &m, kind_fq_codel);
    try codec.appendAttr(gpa, &m, TCA.XSTATS, &x);
    const xs = (try parseQdisc(m.items)).fq_codel_xstats.?;
    try testing.expectEqual(@as(u32, 100), xs.maxpacket);
    try testing.expectEqual(@as(u32, 400), xs.new_flow_count);
    try testing.expectEqual(@as(u32, 900), xs.drop_overmemory);

    var m2: std.ArrayList(u8) = .empty;
    defer m2.deinit(gpa);
    try statsFixture(gpa, &m2, kind_fq_codel);
    try codec.appendAttr(gpa, &m2, TCA.XSTATS, x[0..39]);
    try testing.expect((try parseQdisc(m2.items)).fq_codel_xstats == null);
    le32(&x, 0, 1); // TCA_FQ_CODEL_XSTATS_CLASS
    var m3: std.ArrayList(u8) = .empty;
    defer m3.deinit(gpa);
    try statsFixture(gpa, &m3, kind_fq_codel);
    try codec.appendAttr(gpa, &m3, TCA.XSTATS, &x);
    try testing.expect((try parseQdisc(m3.items)).fq_codel_xstats == null);
}

// ── statistics decoding: delta mutation audit ────────────────────
// The tests below were added for survivors: hardware counters, the 64-bit rate
// estimator, attribute order, exact minimum sizes, short attributes, the
// STATS2 -> STATS fallback, a class carrying only the legacy attribute, every
// fq_codel xstats field, and an XSTATS on a kind that is not fq_codel.

fn statsOfNest(gpa: std.mem.Allocator, nest: []const u8) !?Stats {
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try statsFixture(gpa, &m, "htb");
    try codec.appendAttr(gpa, &m, TCA.STATS2, nest);
    return (try parseQdisc(m.items)).stats;
}

test "stats: BASIC_HW and RATE_EST64 decode; RATE_EST64 wins over RATE_EST in either order" {
    const gpa = testing.allocator;
    var hw: [16]u8 = @splat(0);
    le64(&hw, 0, 42_000_000_000);
    le32(&hw, 8, 7);
    var r64: [16]u8 = undefined;
    le64(&r64, 0, 9_000_000_000);
    le64(&r64, 8, 8_000_000_000);
    var r32: [8]u8 = @splat(0);
    le32(&r32, 0, 5);
    le32(&r32, 4, 6);

    var n: std.ArrayList(u8) = .empty;
    defer n.deinit(gpa);
    try codec.appendAttr(gpa, &n, TCA_STATS2.BASIC_HW, &hw);
    try codec.appendAttr(gpa, &n, TCA_STATS2.RATE_EST, &r32);
    try codec.appendAttr(gpa, &n, TCA_STATS2.RATE_EST64, &r64);
    const a = (try statsOfNest(gpa, n.items)).?;
    try testing.expectEqual(@as(u64, 42_000_000_000), a.hw_bytes);
    try testing.expectEqual(@as(u64, 7), a.hw_packets);
    try testing.expectEqual(@as(u64, 9_000_000_000), a.bps);
    try testing.expectEqual(@as(u64, 8_000_000_000), a.pps);

    // RATE_EST64 first: the later 32-bit RATE_EST must not overwrite it.
    n.clearRetainingCapacity();
    try codec.appendAttr(gpa, &n, TCA_STATS2.RATE_EST64, &r64);
    try codec.appendAttr(gpa, &n, TCA_STATS2.RATE_EST, &r32);
    const b = (try statsOfNest(gpa, n.items)).?;
    try testing.expectEqual(@as(u64, 9_000_000_000), b.bps);
    try testing.expectEqual(@as(u64, 8_000_000_000), b.pps);
}

test "stats: each of BASIC, QUEUE, RATE_EST, RATE_EST64 alone makes the counters present" {
    const gpa = testing.allocator;
    const sizes = [_]struct { t: u16, len: usize }{
        .{ .t = TCA_STATS2.BASIC, .len = 12 },
        .{ .t = TCA_STATS2.QUEUE, .len = 20 },
        .{ .t = TCA_STATS2.RATE_EST, .len = 8 },
        .{ .t = TCA_STATS2.RATE_EST64, .len = 16 },
    };
    for (sizes) |sz| {
        var body: [20]u8 = @splat(3);
        var n: std.ArrayList(u8) = .empty;
        defer n.deinit(gpa);
        try codec.appendAttr(gpa, &n, sz.t, body[0..sz.len]);
        try testing.expect((try statsOfNest(gpa, n.items)) != null);
    }
    // BASIC_HW and PKT64 alone do not: nothing usable was counted.
    var body: [16]u8 = @splat(3);
    var n: std.ArrayList(u8) = .empty;
    defer n.deinit(gpa);
    try codec.appendAttr(gpa, &n, TCA_STATS2.BASIC_HW, &body);
    try codec.appendAttr(gpa, &n, TCA_STATS2.PKT64, body[0..8]);
    try testing.expect((try statsOfNest(gpa, n.items)) == null);
}

test "stats: PKT64 is authoritative whatever the attribute order" {
    const gpa = testing.allocator;
    var basic: [16]u8 = @splat(0);
    le64(&basic, 0, 100);
    le32(&basic, 8, 1000);
    var p: [8]u8 = undefined;
    le64(&p, 0, 5_000_000_000);
    var n: std.ArrayList(u8) = .empty;
    defer n.deinit(gpa);
    try codec.appendAttr(gpa, &n, TCA_STATS2.PKT64, &p);
    try codec.appendAttr(gpa, &n, TCA_STATS2.BASIC, &basic);
    const s = (try statsOfNest(gpa, n.items)).?;
    try testing.expectEqual(@as(u64, 5_000_000_000), s.packets);
    try testing.expectEqual(@as(u64, 100), s.bytes);
}

test "stats: sub-attributes of exactly the minimum size decode, one byte shorter are ignored" {
    const gpa = testing.allocator;
    var basic: [16]u8 = @splat(0);
    le64(&basic, 0, 100);
    le32(&basic, 8, 1000);
    var b12: [12]u8 = @splat(0);
    le64(&b12, 0, 77);
    le32(&b12, 8, 3);
    var r64: [16]u8 = @splat(0);
    le64(&r64, 0, 11);
    le64(&r64, 8, 12);
    var p8: [8]u8 = undefined;
    le64(&p8, 0, 6_000_000_000);

    var n: std.ArrayList(u8) = .empty;
    defer n.deinit(gpa);
    try codec.appendAttr(gpa, &n, TCA_STATS2.BASIC_HW, &b12); // exactly 12
    try codec.appendAttr(gpa, &n, TCA_STATS2.BASIC, &b12); // exactly 12
    try codec.appendAttr(gpa, &n, TCA_STATS2.RATE_EST64, &r64); // exactly 16
    try codec.appendAttr(gpa, &n, TCA_STATS2.PKT64, &p8); // exactly 8
    const s = (try statsOfNest(gpa, n.items)).?;
    try testing.expectEqual(@as(u64, 77), s.hw_bytes);
    try testing.expectEqual(@as(u64, 3), s.hw_packets);
    try testing.expectEqual(@as(u64, 77), s.bytes);
    try testing.expectEqual(@as(u64, 11), s.bps);
    try testing.expectEqual(@as(u64, 12), s.pps);
    try testing.expectEqual(@as(u64, 6_000_000_000), s.packets);

    // One byte short each: ignored, and (BASIC full) the rest still decodes.
    n.clearRetainingCapacity();
    try codec.appendAttr(gpa, &n, TCA_STATS2.BASIC, &basic);
    try codec.appendAttr(gpa, &n, TCA_STATS2.BASIC_HW, b12[0..11]);
    try codec.appendAttr(gpa, &n, TCA_STATS2.RATE_EST, r64[0..7]);
    try codec.appendAttr(gpa, &n, TCA_STATS2.RATE_EST64, r64[0..15]);
    try codec.appendAttr(gpa, &n, TCA_STATS2.PKT64, p8[0..7]);
    const t = (try statsOfNest(gpa, n.items)).?;
    try testing.expectEqual(@as(u64, 0), t.hw_bytes);
    try testing.expectEqual(@as(u64, 0), t.hw_packets);
    try testing.expectEqual(@as(u64, 0), t.bps);
    try testing.expectEqual(@as(u64, 0), t.pps);
    try testing.expectEqual(@as(u64, 1000), t.packets);
}

test "stats: a STATS2 with nothing usable falls back to the legacy TCA_STATS; a class too" {
    const gpa = testing.allocator;
    var legacy: [36]u8 = @splat(0);
    le64(&legacy, 0, 555);
    le32(&legacy, 8, 5);
    var only: std.ArrayList(u8) = .empty;
    defer only.deinit(gpa);
    try codec.appendAttr(gpa, &only, TCA_STATS2.BASIC, &@as([11]u8, @splat(1)));

    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try statsFixture(gpa, &m, "htb");
    try codec.appendAttr(gpa, &m, TCA.STATS2, only.items);
    try codec.appendAttr(gpa, &m, TCA.STATS, &legacy); // exactly tc_stats_len
    const q = (try parseQdisc(m.items)).stats.?;
    try testing.expectEqual(@as(u64, 555), q.bytes);
    try testing.expectEqual(@as(u64, 5), q.packets);

    // A class carrying only the legacy attribute.
    var m2: std.ArrayList(u8) = .empty;
    defer m2.deinit(gpa);
    try statsFixture(gpa, &m2, "htb");
    try codec.appendAttr(gpa, &m2, TCA.STATS, &legacy);
    const c = (try parseClass(m2.items)).stats.?;
    try testing.expectEqual(@as(u64, 555), c.bytes);
    try testing.expectEqual(@as(u64, 5), c.packets);
}

test "stats: every fq_codel xstats field lands in its own member; other kinds ignore XSTATS" {
    const gpa = testing.allocator;
    var x: [40]u8 = @splat(0);
    for (1..10) |i| le32(&x, i * 4, @intCast(i * 100));
    var m: std.ArrayList(u8) = .empty;
    defer m.deinit(gpa);
    try statsFixture(gpa, &m, kind_fq_codel);
    try codec.appendAttr(gpa, &m, TCA.XSTATS, &x);
    const xs = (try parseQdisc(m.items)).fq_codel_xstats.?;
    try testing.expectEqual(@as(u32, 100), xs.maxpacket);
    try testing.expectEqual(@as(u32, 200), xs.drop_overlimit);
    try testing.expectEqual(@as(u32, 300), xs.ecn_mark);
    try testing.expectEqual(@as(u32, 400), xs.new_flow_count);
    try testing.expectEqual(@as(u32, 500), xs.new_flows_len);
    try testing.expectEqual(@as(u32, 600), xs.old_flows_len);
    try testing.expectEqual(@as(u32, 700), xs.ce_mark);
    try testing.expectEqual(@as(u32, 800), xs.memory_usage);
    try testing.expectEqual(@as(u32, 900), xs.drop_overmemory);

    // The same bytes on an htb qdisc are another kind's private statistics.
    var m2: std.ArrayList(u8) = .empty;
    defer m2.deinit(gpa);
    try statsFixture(gpa, &m2, "htb");
    try codec.appendAttr(gpa, &m2, TCA.XSTATS, &x);
    try testing.expect((try parseQdisc(m2.items)).fq_codel_xstats == null);
}
