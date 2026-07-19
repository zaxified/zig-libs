// SPDX-License-Identifier: MIT
//! tc — pure-Zig Linux traffic control over rtnetlink, v1 scoped to the
//! **netem** qdisc (network emulation: delay/jitter/loss/duplicate/reorder/
//! corrupt/rate). This is the write side the `netlink` module deliberately
//! omits ("read/dump only") — `RTM_NEWQDISC`/`RTM_DELQDISC` construction +
//! `NLMSG_ERROR` ACK parsing, plus a read-back via `RTM_GETQDISC` for
//! verification. No `tc` shell-out, no libc.
//!
//! ```zig
//! var sock = try tc.Socket.open(gpa);
//! defer sock.close();
//! try sock.add(ifindex, .{ .delay_ns = 100 * std.time.ns_per_ms, .loss_pct = 1.0 });
//! const q = (try sock.show(ifindex)).?;
//! try sock.del(ifindex);
//! ```
//!
//! Both write ops need **CAP_NET_ADMIN**; `show` (RTM_GETQDISC dump) does not.
//!
//! Scope: v1 is the netem qdisc only — attach it as the **root** qdisc of an
//! interface (`tcm_parent = TC_H_ROOT`, `tcm_handle = 1:0`). Classful qdiscs
//! (htb/hfsc), filters (u32/bpf/flower), and other leaf qdiscs (tbf/fq_codel/
//! sfq/…) are out of scope — see SPEC.md.
//!
//! The wire codec (nlmsghdr framing + rtattr/nlattr TLV walking) is reused
//! from the sibling `netlink` module (`codec.Message`/`Attr`/`AttrIterator`);
//! this module adds its own `NETLINK_ROUTE` socket and the write+ACK path
//! (`netlink.Socket` is read/dump-only by design).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
const codec = netlink.codec;

pub const meta = .{
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .reentrant, // no globals; one Socket per thread/loop
    .model_after = "iproute2 `tc` (attribute-shape/behavior only; wire layout is clean-room from the kernel UAPI linux/pkt_sched.h + linux/rtnetlink.h — see NOTICE)",
    .deps = .{"netlink"},
};

// ── kernel UAPI constants ───────────────────────────────────────────────────
// linux/rtnetlink.h (struct tcmsg, TCA_*) + linux/pkt_sched.h (struct
// tc_netem_qopt and friends, TCA_NETEM_*). std.os.linux only defines the bare
// RTM_NEWQDISC/RTM_DELQDISC/RTM_GETQDISC message-type numbers — everything
// else here is this module's own gap-fill.

/// rtnetlink message types (std.os.linux.NetlinkMessageType values).
pub const RTM_NEWQDISC: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_NEWQDISC);
pub const RTM_DELQDISC: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_DELQDISC);
pub const RTM_GETQDISC: u16 = @intFromEnum(linux.NetlinkMessageType.RTM_GETQDISC);

/// sizeof(struct tcmsg), linux/rtnetlink.h: u8 family, u8 pad1, u16 pad2,
/// i32 ifindex, u32 handle, u32 parent, u32 info.
pub const tcmsg_len = 20;

/// sizeof(struct tc_netem_qopt), linux/pkt_sched.h: u32 latency, limit, loss,
/// gap, duplicate, jitter.
pub const tc_netem_qopt_len = 24;

/// TC_H_ROOT (linux/rtnetlink.h) — "no parent, this is the root qdisc".
pub const TC_H_ROOT: u32 = 0xFFFFFFFF;
/// The handle this module always assigns a netem root qdisc: major 1, minor
/// 0 ("1:0"), matching what `tc qdisc add … root` picks by convention.
pub const netem_handle: u32 = 0x00010000;

/// Write-path NLM_F_* flags (linux/netlink.h). Not in `netlink.codec` because
/// that module's scope is read/dump only (REQUEST/DUMP/ACK/MULTI cover it);
/// these three are only meaningful for RTM_NEW*/RTM_DEL* writes, which live
/// here.
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

/// Qdisc attribute types (linux/rtnetlink.h enum, TCA_*) — attributes on the
/// tcmsg fixed header.
pub const TCA = struct {
    pub const UNSPEC: u16 = 0;
    pub const KIND: u16 = 1;
    pub const OPTIONS: u16 = 2;
    pub const STATS: u16 = 3;
};

/// netem-specific extended attribute types (linux/pkt_sched.h enum,
/// TCA_NETEM_*) — nested inside `TCA.OPTIONS`, after the fixed
/// `tc_netem_qopt` bytes. v1 only builds/parses CORR, REORDER, CORRUPT,
/// RATE, LATENCY64, JITTER64 (DELAY_DIST/ECN/RATE64/SLOT* are out of scope).
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

/// The `TCA_KIND` string identifying a netem qdisc.
pub const kind_netem = "netem";

// ── typed netem options (public API input) ──────────────────────────────────

/// A netem configuration, in ergonomic units (nanoseconds, percent 0..100).
/// The module encodes this into the kernel wire form (see SPEC.md for the
/// exact `tc_netem_qopt` + extended-attribute layout and the psched-tick
/// decision).
///
/// All `*_pct` fields are percentages in `[0, 100]`; `Socket.add`/`.change`
/// return `error.InvalidPercent` for anything outside that range (including
/// NaN).
pub const Netem = struct {
    /// FIFO packet limit ("tc … limit N"); the kernel/tc default is 1000.
    limit: u32 = 1000,
    /// Base one-way added delay ("delay Xms"), nanoseconds. 0 = no delay.
    /// Encoded via `TCA_NETEM_LATENCY64` (see SPEC.md), never the legacy
    /// psched-tick `tc_netem_qopt.latency` field.
    delay_ns: u64 = 0,
    /// Delay jitter ("delay Xms Yms"), nanoseconds. 0 = none. Encoded via
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
    /// bypasses the delay queue, overtaking earlier delayed packets. 0 =
    /// off (probabilistic reorder only). Only meaningful alongside a
    /// nonzero `delay_ns` — mirrors `tc`.
    reorder_gap: u32 = 0,
    /// Random packet corruption probability percent ("corrupt Z%").
    corrupt_pct: f64 = 0,
    /// Corrupt correlation percent.
    corrupt_correlation_pct: f64 = 0,
    /// Rate limit in bytes/s ("rate Rbit/Rbps" — convert to bytes/s before
    /// setting this). 0 = unlimited. v1 only emits `TCA_NETEM_RATE` (u32);
    /// rates needing `TCA_NETEM_RATE64` are out of scope.
    rate_bytes_per_sec: u32 = 0,
};

/// The wire-level readback of a netem qdisc's options (from `Socket.show`).
/// Deliberately separate from `Netem`: these are the raw scaled/kernel
/// values (no percent reconstruction — avoids float round-trip ambiguity),
/// so a caller that built a `Netem` can assert exact equality against the
/// same `percentToU32`-scaled values it used to build the request.
pub const NetemWire = struct {
    limit: u32 = 0,
    /// Raw scaled probability (`percent/100 * UINT32_MAX`), 0 = none.
    loss: u32 = 0,
    duplicate: u32 = 0,
    /// `tc_netem_qopt.gap` — the deterministic reorder gap.
    gap: u32 = 0,
    /// Legacy `tc_netem_qopt.latency`/`.jitter` fields (psched ticks or a
    /// kernel-derived legacy value on dump — see SPEC.md). This module
    /// always writes 0 here; a dumping kernel may report a nonzero legacy
    /// value derived from the 64-bit ns fields below for old-tool
    /// compatibility. Informational only — prefer `delay_ns`/`jitter_ns`.
    legacy_latency: u32 = 0,
    legacy_jitter: u32 = 0,
    /// `TCA_NETEM_LATENCY64` / `TCA_NETEM_JITTER64`, nanoseconds; 0 if the
    /// attribute was absent.
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

/// One qdisc, as read back by `Socket.show` (RTM_GETQDISC).
pub const Qdisc = struct {
    ifindex: u32,
    handle: u32,
    parent: u32,
    kind_buf: [16]u8 = @splat(0),
    kind_len: u8 = 0,
    /// Decoded netem options, present only when `kind() == "netem"`.
    netem: ?NetemWire = null,

    /// The qdisc kind string ("netem", "noqueue", "fq_codel", …).
    pub fn kind(q: *const Qdisc) []const u8 {
        return q.kind_buf[0..q.kind_len];
    }
};

/// Scale a `[0, 100]` percent to the kernel's `u32` probability scale
/// (`percent/100 * UINT32_MAX`, rounded — matches `tc`'s own scaling).
/// NaN and anything outside `[0, 100]` is rejected.
pub fn percentToU32(pct: f64) error{InvalidPercent}!u32 {
    if (!(pct >= 0.0 and pct <= 100.0)) return error.InvalidPercent;
    const scaled = @round(pct / 100.0 * @as(f64, @floatFromInt(std.math.maxInt(u32))));
    return @intFromFloat(scaled);
}

// ── request building (pure, offline-testable) ───────────────────────────────

pub const BuildError = std.mem.Allocator.Error || error{ InvalidPercent, InvalidDelay };

/// Validate a `delay_ns`/`jitter_ns` value fits the wire's signed 64-bit
/// nanosecond field (`TCA_NETEM_LATENCY64`/`JITTER64`). Mirrors
/// `percentToU32`: reject before any allocation rather than let the later
/// `@intCast(i64, …)` panic (ReleaseSafe) or silently wrap to a negative
/// latency (ReleaseFast).
fn checkDelayNs(ns: u64) error{InvalidDelay}!void {
    if (ns > std.math.maxInt(i64)) return error.InvalidDelay;
}

fn appendTcmsg(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    ifindex: u32,
    handle: u32,
    parent: u32,
) std.mem.Allocator.Error!void {
    var buf: [tcmsg_len]u8 = @splat(0); // family/pad1/pad2/info all 0
    std.mem.writeInt(i32, buf[4..8], @bitCast(ifindex), native_endian);
    std.mem.writeInt(u32, buf[8..12], handle, native_endian);
    std.mem.writeInt(u32, buf[12..16], parent, native_endian);
    try codec.appendPadded(gpa, list, &buf);
}

/// Open a nested attribute (NLA_F_NESTED set, length patched by `nestEnd`).
fn nestBegin(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
) std.mem.Allocator.Error!usize {
    const off = list.items.len;
    var hdr: [codec.attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], 0, native_endian); // patched by nestEnd
    std.mem.writeInt(u16, hdr[2..4], attr_type | codec.NLA_F_NESTED, native_endian);
    try list.appendSlice(gpa, &hdr);
    return off;
}

fn nestEnd(list: *std.ArrayList(u8), off: usize) void {
    const total: u16 = @intCast(list.items.len - off);
    std.mem.writeInt(u16, list.items[off..][0..2], total, native_endian);
}

fn appendAttrRaw(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    data: []const u8,
) std.mem.Allocator.Error!void {
    codec.appendAttr(gpa, list, attr_type, data) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // all our payloads are <= 16 bytes
        error.OutOfMemory => return error.OutOfMemory,
    };
}

/// Build one `RTM_NEWQDISC` request: nlmsghdr + tcmsg (root, handle 1:0) +
/// `TCA_KIND` "netem" + `TCA_OPTIONS` (qopt + extended attrs). `flags` picks
/// add (`NLM_F_CREATE|NLM_F_EXCL`) vs change/replace (`NLM_F_CREATE|
/// NLM_F_REPLACE`) semantics; both always include `NLM_F_REQUEST|NLM_F_ACK`.
fn buildSetRequest(
    gpa: std.mem.Allocator,
    seq: u32,
    flags: u16,
    ifindex: u32,
    netem: Netem,
) BuildError![]u8 {
    // Validate + pre-scale every percent field before allocating anything.
    const loss = try percentToU32(netem.loss_pct);
    const loss_corr = try percentToU32(netem.loss_correlation_pct);
    const dup = try percentToU32(netem.duplicate_pct);
    const dup_corr = try percentToU32(netem.duplicate_correlation_pct);
    const delay_corr = try percentToU32(netem.delay_correlation_pct);
    const reorder_prob = try percentToU32(netem.reorder_pct);
    const reorder_corr = try percentToU32(netem.reorder_correlation_pct);
    const corrupt_prob = try percentToU32(netem.corrupt_pct);
    const corrupt_corr = try percentToU32(netem.corrupt_correlation_pct);
    try checkDelayNs(netem.delay_ns);
    try checkDelayNs(netem.jitter_ns);

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, RTM_NEWQDISC, flags, seq, 0);
    try appendTcmsg(gpa, &list, ifindex, netem_handle, TC_H_ROOT);
    codec.appendAttrString(gpa, &list, TCA.KIND, kind_netem) catch |err| switch (err) {
        error.AttrTooLong => unreachable, // "netem" is 5 bytes
        error.OutOfMemory => return error.OutOfMemory,
    };

    const opt_off = try nestBegin(gpa, &list, TCA.OPTIONS);
    {
        // struct tc_netem_qopt: latency(0, real value goes via LATENCY64),
        // limit, loss, gap, duplicate, jitter(0, real value via JITTER64).
        var qopt: [tc_netem_qopt_len]u8 = @splat(0);
        std.mem.writeInt(u32, qopt[4..8], netem.limit, native_endian);
        std.mem.writeInt(u32, qopt[8..12], loss, native_endian);
        std.mem.writeInt(u32, qopt[12..16], netem.reorder_gap, native_endian);
        std.mem.writeInt(u32, qopt[16..20], dup, native_endian);
        try codec.appendPadded(gpa, &list, &qopt); // already 4-aligned (24 B)
    }
    if (delay_corr != 0 or loss_corr != 0 or dup_corr != 0) {
        var corr: [12]u8 = undefined;
        std.mem.writeInt(u32, corr[0..4], delay_corr, native_endian);
        std.mem.writeInt(u32, corr[4..8], loss_corr, native_endian);
        std.mem.writeInt(u32, corr[8..12], dup_corr, native_endian);
        try appendAttrRaw(gpa, &list, TCA_NETEM.CORR, &corr);
    }
    if (reorder_prob != 0 or netem.reorder_gap != 0) {
        var reo: [8]u8 = undefined;
        std.mem.writeInt(u32, reo[0..4], reorder_prob, native_endian);
        std.mem.writeInt(u32, reo[4..8], reorder_corr, native_endian);
        try appendAttrRaw(gpa, &list, TCA_NETEM.REORDER, &reo);
    }
    if (corrupt_prob != 0) {
        var cor: [8]u8 = undefined;
        std.mem.writeInt(u32, cor[0..4], corrupt_prob, native_endian);
        std.mem.writeInt(u32, cor[4..8], corrupt_corr, native_endian);
        try appendAttrRaw(gpa, &list, TCA_NETEM.CORRUPT, &cor);
    }
    if (netem.rate_bytes_per_sec != 0) {
        // struct tc_netem_rate: rate, packet_overhead(0), cell_size(0),
        // cell_overhead(0) — the overhead/cell knobs are out of scope.
        var rate: [16]u8 = @splat(0);
        std.mem.writeInt(u32, rate[0..4], netem.rate_bytes_per_sec, native_endian);
        try appendAttrRaw(gpa, &list, TCA_NETEM.RATE, &rate);
    }
    if (netem.delay_ns != 0) {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(i64, &raw, @intCast(netem.delay_ns), native_endian);
        try appendAttrRaw(gpa, &list, TCA_NETEM.LATENCY64, &raw);
    }
    if (netem.jitter_ns != 0) {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(i64, &raw, @intCast(netem.jitter_ns), native_endian);
        try appendAttrRaw(gpa, &list, TCA_NETEM.JITTER64, &raw);
    }
    nestEnd(&list, opt_off);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build one `RTM_DELQDISC` request targeting the root netem qdisc.
fn buildDelRequest(gpa: std.mem.Allocator, seq: u32, ifindex: u32) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, RTM_DELQDISC, codec.NLM_F_REQUEST | codec.NLM_F_ACK, seq, 0);
    try appendTcmsg(gpa, &list, ifindex, netem_handle, TC_H_ROOT);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build one `RTM_GETQDISC` dump request. `ifindex` is passed in the fixed
/// header as a courtesy to kernels that honor it, and is always re-checked
/// client-side in `Socket.show` (same belt-and-braces approach `netlink`
/// takes for its own filters).
fn buildDumpRequest(gpa: std.mem.Allocator, seq: u32, ifindex: u32) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(gpa, &list, RTM_GETQDISC, codec.NLM_F_REQUEST | codec.NLM_F_DUMP, seq, 0);
    try appendTcmsg(gpa, &list, ifindex, 0, 0); // handle/parent unspecific
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── reply parsing (pure, offline-testable, fuzzed) ──────────────────────────

/// Parse an `RTM_NEWQDISC` payload (struct tcmsg + TCA_* attributes) into a
/// typed `Qdisc`. Unlike `netlink`'s `parse*` functions (which return `null`
/// for a degenerate entry worth skipping, e.g. an address with no usable
/// IP), every qdisc dump entry is inherently usable, so this returns `Qdisc`
/// directly rather than `?Qdisc`.
pub fn parseQdisc(payload: []const u8) codec.Error!Qdisc {
    if (payload.len < tcmsg_len) return error.Truncated;
    var q: Qdisc = .{
        .ifindex = @bitCast(std.mem.readInt(i32, payload[4..8], native_endian)),
        .handle = std.mem.readInt(u32, payload[8..12], native_endian),
        .parent = std.mem.readInt(u32, payload[12..16], native_endian),
    };
    var options_data: ?[]const u8 = null;
    var it: codec.AttrIterator = .{ .buf = payload[tcmsg_len..] };
    while (try it.next()) |a| switch (a.type) {
        TCA.KIND => {
            const s = a.asString();
            if (s.len > q.kind_buf.len) return error.BadLength;
            @memcpy(q.kind_buf[0..s.len], s);
            q.kind_len = @intCast(s.len);
        },
        TCA.OPTIONS => options_data = a.data,
        else => {},
    };
    if (options_data) |opt| {
        if (std.mem.eql(u8, q.kind(), kind_netem)) {
            q.netem = try parseNetemOptions(opt);
        }
    }
    return q;
}

/// Parse a `TCA_OPTIONS` payload for a netem qdisc: fixed `tc_netem_qopt`
/// (24 B) followed by extended `TCA_NETEM_*` TLVs. Sub-attributes with an
/// unexpected length are ignored rather than rejected (defensive, like
/// `netlink`'s `ipLen` check) — one odd attribute shouldn't fail the whole
/// parse.
fn parseNetemOptions(data: []const u8) codec.Error!NetemWire {
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

// ── errno mapping ───────────────────────────────────────────────────────────

pub const RequestError = error{
    OutOfMemory,
    SendFailed,
    RecvFailed,
    /// A reply failed wire-format validation (bounds/length checks).
    MalformedReply,
    /// Missing CAP_NET_ADMIN — add/change/del all need it.
    AccessDenied,
    /// `add` with an existing root qdisc (NLM_F_EXCL).
    Exists,
    /// `del` on an interface with no matching qdisc.
    NotFound,
    /// No such interface (bad ifindex).
    NoSuchDevice,
    InvalidRequest,
    NotSupported,
    SystemResources,
    Unexpected,
};

pub const SetError = RequestError || BuildError;
pub const DelError = RequestError;
pub const GetError = RequestError;

fn errnoToError(code: i32) RequestError {
    if (code >= 0 or code == std.math.minInt(i32)) return error.Unexpected;
    return switch (@as(u32, @intCast(-code))) {
        @intFromEnum(linux.E.PERM), @intFromEnum(linux.E.ACCES) => error.AccessDenied,
        @intFromEnum(linux.E.EXIST) => error.Exists,
        @intFromEnum(linux.E.NOENT) => error.NotFound,
        @intFromEnum(linux.E.NODEV) => error.NoSuchDevice,
        @intFromEnum(linux.E.INVAL) => error.InvalidRequest,
        @intFromEnum(linux.E.OPNOTSUPP) => error.NotSupported,
        @intFromEnum(linux.E.NOBUFS), @intFromEnum(linux.E.NOMEM) => error.SystemResources,
        else => error.Unexpected,
    };
}

// ── socket transport ────────────────────────────────────────────────────────
// A small, independent NETLINK_ROUTE socket (mirrors netlink.Socket.open's
// raw-syscall shape) — `netlink.Socket` is read/dump-only by design, so the
// write+ACK path lives here rather than reaching into its internals.

pub const OpenError = error{
    OutOfMemory,
    AccessDenied,
    ProtocolNotSupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    Unexpected,
};

const initial_recv_buf_len = 8192;
const max_recv_buf_len = 1 << 24;
const max_dump_attempts = 4; // NLM_F_DUMP_INTR restarts before giving up

/// A blocking `NETLINK_ROUTE` socket for netem qdisc writes + read-back. One
/// instance per thread/loop; no shared state.
pub const Socket = struct {
    gpa: std.mem.Allocator,
    fd: i32,
    portid: u32,
    seq: u32,
    buf: []u8,

    pub fn open(gpa: std.mem.Allocator) OpenError!Socket {
        if (comptime builtin.os.tag != .linux)
            @compileError("tc.Socket is Linux-only (AF_NETLINK raw syscalls)");

        const rc = linux.socket(
            linux.AF.NETLINK,
            linux.SOCK.RAW | linux.SOCK.CLOEXEC,
            linux.NETLINK.ROUTE,
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .AFNOSUPPORT, .PROTONOSUPPORT => return error.ProtocolNotSupported,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        const fd: i32 = @intCast(rc);
        errdefer _ = linux.close(fd);

        const sa: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        switch (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.nl)))) {
            .SUCCESS => {},
            .NOBUFS, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        var bound: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        var blen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
        switch (linux.errno(linux.getsockname(fd, @ptrCast(&bound), &blen))) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }

        const buf = try gpa.alloc(u8, initial_recv_buf_len);
        return .{ .gpa = gpa, .fd = fd, .portid = bound.pid, .seq = 0, .buf = buf };
    }

    pub fn close(self: *Socket) void {
        self.gpa.free(self.buf);
        _ = linux.close(self.fd);
        self.* = undefined;
    }

    /// Attach a netem root qdisc (`NLM_F_CREATE|NLM_F_EXCL` — fails
    /// `error.Exists` if one is already attached). Needs CAP_NET_ADMIN.
    pub fn add(self: *Socket, ifindex: u32, netem: Netem) SetError!void {
        try self.setNetem(ifindex, netem, NLM_F_CREATE | NLM_F_EXCL);
    }

    /// Create-or-replace the root qdisc with a new netem config
    /// (`NLM_F_CREATE|NLM_F_REPLACE` — idempotent, unlike `add`). Needs
    /// CAP_NET_ADMIN.
    pub fn change(self: *Socket, ifindex: u32, netem: Netem) SetError!void {
        try self.setNetem(ifindex, netem, NLM_F_CREATE | NLM_F_REPLACE);
    }

    fn setNetem(self: *Socket, ifindex: u32, netem: Netem, extra_flags: u16) SetError!void {
        const seq = self.nextSeq();
        const req = try buildSetRequest(self.gpa, seq, codec.NLM_F_REQUEST | codec.NLM_F_ACK | extra_flags, ifindex, netem);
        defer self.gpa.free(req);
        try self.send(req);
        try self.awaitAck(seq);
    }

    /// Remove the root qdisc (reverting the interface to its default).
    /// Needs CAP_NET_ADMIN.
    pub fn del(self: *Socket, ifindex: u32) DelError!void {
        const seq = self.nextSeq();
        const req = try buildDelRequest(self.gpa, seq, ifindex);
        defer self.gpa.free(req);
        try self.send(req);
        try self.awaitAck(seq);
    }

    /// Read back the qdisc attached to `ifindex` via a filtered
    /// `RTM_GETQDISC` dump — every interface always has *some* root qdisc
    /// (`noqueue`/`pfifo_fast`/… by default), so this returns `null` only
    /// when the interface itself doesn't exist / reports nothing. Does not
    /// need CAP_NET_ADMIN.
    pub fn show(self: *Socket, ifindex: u32) GetError!?Qdisc {
        var attempt: usize = 0;
        retry: while (true) {
            attempt += 1;
            const seq = self.nextSeq();
            const req = try buildDumpRequest(self.gpa, seq, ifindex);
            defer self.gpa.free(req);
            try self.send(req);

            var found: ?Qdisc = null;
            while (true) {
                const dgram = try self.recvDatagram();
                var it: codec.MessageIterator = .{ .buf = dgram };
                while (it.next() catch return error.MalformedReply) |m| {
                    if (m.pid != self.portid or m.seq != seq) continue;
                    if (m.flags & codec.NLM_F_DUMP_INTR != 0) {
                        if (attempt < max_dump_attempts) continue :retry;
                        return error.Unexpected;
                    }
                    switch (m.type) {
                        codec.NLMSG_DONE => return found,
                        codec.NLMSG_ERROR => {
                            const code = m.errorCode() catch return error.MalformedReply;
                            if (code == 0) continue; // stray ACK
                            return errnoToError(code);
                        },
                        codec.NLMSG_NOOP => {},
                        codec.NLMSG_OVERRUN => return error.SystemResources,
                        else => {
                            if (m.type != RTM_NEWQDISC) continue;
                            const q = parseQdisc(m.payload) catch return error.MalformedReply;
                            if (q.ifindex == ifindex) found = q;
                        },
                    }
                }
            }
        }
    }

    fn nextSeq(self: *Socket) u32 {
        self.seq +%= 1;
        if (self.seq == 0) self.seq = 1;
        return self.seq;
    }

    fn send(self: *Socket, msg: []const u8) RequestError!void {
        const dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        while (true) {
            const rc = linux.sendto(self.fd, msg.ptr, msg.len, 0, @ptrCast(&dst), @sizeOf(linux.sockaddr.nl));
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                .ACCES, .PERM => return error.AccessDenied,
                else => return error.SendFailed,
            }
        }
    }

    fn recvDatagram(self: *Socket) RequestError![]const u8 {
        while (true) {
            const prc = linux.recvfrom(self.fd, self.buf.ptr, self.buf.len, linux.MSG.PEEK | linux.MSG.TRUNC, null, null);
            switch (linux.errno(prc)) {
                .SUCCESS => {},
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.RecvFailed,
            }
            if (prc > self.buf.len) {
                if (prc > max_recv_buf_len) return error.MalformedReply;
                const new_len = std.mem.alignForward(usize, prc, initial_recv_buf_len);
                self.buf = self.gpa.realloc(self.buf, new_len) catch return error.OutOfMemory;
                continue;
            }

            var src: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
            var slen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
            const rc = linux.recvfrom(self.fd, self.buf.ptr, self.buf.len, 0, @ptrCast(&src), &slen);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.RecvFailed,
            }
            if (slen >= @sizeOf(linux.sockaddr.nl) and src.pid != 0) continue; // not the kernel
            return self.buf[0..rc];
        }
    }

    fn awaitAck(self: *Socket, seq: u32) RequestError!void {
        while (true) {
            const dgram = try self.recvDatagram();
            var it: codec.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                if (m.pid != self.portid or m.seq != seq) continue;
                if (m.type != codec.NLMSG_ERROR) continue;
                const code = m.errorCode() catch return error.MalformedReply;
                if (code == 0) return; // ACK
                return errnoToError(code);
            }
        }
    }
};

// ── offline tests: golden bytes + encode/decode round-trip + fuzz ──────────

const testing = std.testing;

test "percentToU32: range + rounding" {
    try testing.expectEqual(@as(u32, 0), try percentToU32(0));
    try testing.expectEqual(std.math.maxInt(u32), try percentToU32(100));
    try testing.expectEqual(@as(u32, 42949673), try percentToU32(1.0));
    try testing.expectEqual(@as(u32, 2147483648), try percentToU32(50.0)); // 0.5 * 2^32, exact
    try testing.expectError(error.InvalidPercent, percentToU32(-0.1));
    try testing.expectError(error.InvalidPercent, percentToU32(100.1));
    try testing.expectError(error.InvalidPercent, percentToU32(std.math.nan(f64)));
}

test "wire constants agree with the kernel UAPI" {
    try testing.expectEqual(@as(u16, 36), RTM_NEWQDISC);
    try testing.expectEqual(@as(u16, 37), RTM_DELQDISC);
    try testing.expectEqual(@as(u16, 38), RTM_GETQDISC);
    try testing.expectEqual(@as(u16, 1), TCA.KIND);
    try testing.expectEqual(@as(u16, 2), TCA.OPTIONS);
    try testing.expectEqual(@as(u16, 1), TCA_NETEM.CORR);
    try testing.expectEqual(@as(u16, 3), TCA_NETEM.REORDER);
    try testing.expectEqual(@as(u16, 4), TCA_NETEM.CORRUPT);
    try testing.expectEqual(@as(u16, 6), TCA_NETEM.RATE);
    try testing.expectEqual(@as(u16, 10), TCA_NETEM.LATENCY64);
    try testing.expectEqual(@as(u16, 11), TCA_NETEM.JITTER64);
}

// Hand-verified golden bytes for `add(ifindex=5, delay 100ms/jitter 10ms/
// loss 1%)`. Computed independently (byte-by-byte, see SPEC.md "Verification"
// for the derivation) — this is the module's primary regression guard
// against any drift in the tcmsg/qopt/attr encoding.
test "golden: RTM_NEWQDISC add request bytes (delay + jitter + loss)" {
    if (native_endian != .little) return error.SkipZigTest; // golden bytes are LE

    const req = try buildSetRequest(
        testing.allocator,
        1,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
        5,
        .{
            .delay_ns = 100_000_000,
            .jitter_ns = 10_000_000,
            .loss_pct = 1.0,
        },
    );
    defer testing.allocator.free(req);

    const expected = [_]u8{
        // nlmsghdr (16 B)
        0x64, 0x00, 0x00, 0x00, // len = 100
        0x24, 0x00, // type = RTM_NEWQDISC (36)
        0x05, 0x06, // flags = REQUEST|ACK|EXCL|CREATE (0x0605)
        0x01, 0x00, 0x00, 0x00, // seq = 1
        0x00, 0x00, 0x00, 0x00, // pid = 0
        // tcmsg (20 B)
        0x00, 0x00, 0x00, 0x00, // family/pad1/pad2
        0x05, 0x00, 0x00, 0x00, // ifindex = 5
        0x00, 0x00, 0x01, 0x00, // handle = 1:0
        0xff, 0xff, 0xff, 0xff, // parent = TC_H_ROOT
        0x00, 0x00, 0x00, 0x00, // info
        // TCA_KIND = "netem\0" + 2 pad (12 B)
        0x0a, 0x00, 0x01, 0x00,
        'n',  'e',  't',  'e',
        'm',  0x00, 0x00, 0x00,
        // TCA_OPTIONS, nested, len = 52 (4 + 48) (4 B header)
        0x34, 0x00, 0x02, 0x80,
        // tc_netem_qopt (24 B): latency=0, limit=1000, loss=42949673,
        // gap=0, duplicate=0, jitter=0
        0x00, 0x00, 0x00, 0x00,
        0xe8, 0x03, 0x00, 0x00,
        0x29, 0x5c, 0x8f, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // TCA_NETEM_LATENCY64 = 100_000_000 ns (12 B)
        0x0c, 0x00, 0x0a, 0x00,
        0x00, 0xe1, 0xf5, 0x05,
        0x00, 0x00, 0x00, 0x00,
        // TCA_NETEM_JITTER64 = 10_000_000 ns (12 B)
        0x0c, 0x00, 0x0b, 0x00,
        0x80, 0x96, 0x98, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    try testing.expectEqualSlices(u8, &expected, req);
}

test "golden: RTM_DELQDISC request bytes" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildDelRequest(testing.allocator, 7, 3);
    defer testing.allocator.free(req);
    const expected = [_]u8{
        0x24, 0x00, 0x00, 0x00, // len = 36
        0x25, 0x00, // type = RTM_DELQDISC (37)
        0x05, 0x00, // flags = REQUEST|ACK
        0x07, 0x00, 0x00, 0x00, // seq = 7
        0x00, 0x00, 0x00, 0x00, // pid
        0x00, 0x00, 0x00, 0x00, // family/pad1/pad2
        0x03, 0x00, 0x00, 0x00, // ifindex = 3
        0x00, 0x00, 0x01, 0x00, // handle = 1:0
        0xff, 0xff, 0xff, 0xff, // parent = TC_H_ROOT
        0x00, 0x00, 0x00, 0x00, // info
    };
    try testing.expectEqualSlices(u8, &expected, req);
}

test "golden: RTM_GETQDISC dump request bytes" {
    if (native_endian != .little) return error.SkipZigTest;
    const req = try buildDumpRequest(testing.allocator, 2, 9);
    defer testing.allocator.free(req);
    const expected = [_]u8{
        0x24, 0x00, 0x00, 0x00, // len = 36
        0x26, 0x00, // type = RTM_GETQDISC (38)
        0x01, 0x03, // flags = REQUEST|DUMP (ROOT|MATCH)
        0x02, 0x00, 0x00, 0x00, // seq = 2
        0x00, 0x00, 0x00, 0x00, // pid
        0x00, 0x00, 0x00, 0x00, // family/pad1/pad2
        0x09, 0x00, 0x00, 0x00, // ifindex = 9 (courtesy filter)
        0x00, 0x00, 0x00, 0x00, // handle = unspecific
        0x00, 0x00, 0x00, 0x00, // parent = unspecific
        0x00, 0x00, 0x00, 0x00, // info
    };
    try testing.expectEqualSlices(u8, &expected, req);
}

test "encode/decode round-trip: build an add request, parse it back like a kernel dump reply" {
    const netem: Netem = .{
        .limit = 500,
        .delay_ns = 50_000_000,
        .jitter_ns = 5_000_000,
        .delay_correlation_pct = 25.0,
        .loss_pct = 2.5,
        .loss_correlation_pct = 10.0,
        .duplicate_pct = 0.5,
        .reorder_pct = 1.0,
        .reorder_correlation_pct = 50.0,
        .reorder_gap = 5,
        .corrupt_pct = 0.1,
        .rate_bytes_per_sec = 125_000, // 1 Mbit/s
    };
    const req = try buildSetRequest(testing.allocator, 1, codec.NLM_F_REQUEST | codec.NLM_F_ACK, 42, netem);
    defer testing.allocator.free(req);

    // Skip the nlmsghdr; parseQdisc expects a message *payload* (tcmsg +
    // attrs), matching what Socket.show hands to it from a real dump.
    const payload = req[codec.header_len..];
    const q = try parseQdisc(payload);
    try testing.expectEqual(@as(u32, 42), q.ifindex);
    try testing.expectEqual(netem_handle, q.handle);
    try testing.expectEqual(TC_H_ROOT, q.parent);
    try testing.expectEqualStrings("netem", q.kind());

    const nw = q.netem.?;
    try testing.expectEqual(@as(u32, 500), nw.limit);
    try testing.expectEqual(@as(u32, 5), nw.gap);
    try testing.expectEqual(try percentToU32(2.5), nw.loss);
    try testing.expectEqual(try percentToU32(0.5), nw.duplicate);
    try testing.expectEqual(@as(i64, 50_000_000), nw.delay_ns);
    try testing.expectEqual(@as(i64, 5_000_000), nw.jitter_ns);
    try testing.expectEqual(try percentToU32(25.0), nw.delay_correlation);
    try testing.expectEqual(try percentToU32(10.0), nw.loss_correlation);
    try testing.expectEqual(try percentToU32(1.0), nw.reorder_probability);
    try testing.expectEqual(try percentToU32(50.0), nw.reorder_correlation);
    try testing.expectEqual(try percentToU32(0.1), nw.corrupt_probability);
    try testing.expectEqual(@as(u32, 125_000), nw.rate_bytes_per_sec);
}

test "encode: zero-config netem omits every optional attribute" {
    const req = try buildSetRequest(testing.allocator, 1, codec.NLM_F_REQUEST | codec.NLM_F_ACK, 1, .{});
    defer testing.allocator.free(req);
    // header(16) + tcmsg(20) + TCA_KIND(12) + TCA_OPTIONS hdr(4) + qopt(24)
    try testing.expectEqual(@as(usize, 16 + 20 + 12 + 4 + 24), req.len);

    const q = try parseQdisc(req[codec.header_len..]);
    try testing.expectEqualStrings("netem", q.kind());
    const nw = q.netem.?;
    try testing.expectEqual(@as(u32, 1000), nw.limit); // Netem{} default
    try testing.expectEqual(@as(u32, 0), nw.loss);
    try testing.expectEqual(@as(i64, 0), nw.delay_ns);
    try testing.expectEqual(@as(u32, 0), nw.rate_bytes_per_sec);
}

test "buildSetRequest rejects an out-of-range percent before allocating" {
    try testing.expectError(error.InvalidPercent, buildSetRequest(
        testing.allocator,
        1,
        codec.NLM_F_REQUEST,
        1,
        .{ .loss_pct = 150 },
    ));
}

test "buildSetRequest rejects out-of-range delay/jitter before allocating" {
    // ns > maxInt(i64) must never reach the @intCast — would panic under
    // ReleaseSafe / wrap to a negative LATENCY64 under ReleaseFast.
    const too_big: u64 = @as(u64, std.math.maxInt(i64)) + 1;
    try testing.expectError(error.InvalidDelay, buildSetRequest(
        testing.allocator,
        1,
        codec.NLM_F_REQUEST,
        1,
        .{ .delay_ns = too_big },
    ));
    try testing.expectError(error.InvalidDelay, buildSetRequest(
        testing.allocator,
        1,
        codec.NLM_F_REQUEST,
        1,
        .{ .jitter_ns = too_big },
    ));
    // A normal value must still build fine (max representable i64 is legal).
    const req = try buildSetRequest(
        testing.allocator,
        1,
        codec.NLM_F_REQUEST,
        1,
        .{ .delay_ns = @intCast(std.math.maxInt(i64)), .jitter_ns = 10_000_000 },
    );
    testing.allocator.free(req);
}

test "errnoToError maps NLMSG_ERROR errnos" {
    try testing.expectEqual(error.AccessDenied, errnoToError(-@as(i32, @intFromEnum(linux.E.PERM))));
    try testing.expectEqual(error.Exists, errnoToError(-@as(i32, @intFromEnum(linux.E.EXIST))));
    try testing.expectEqual(error.NotFound, errnoToError(-@as(i32, @intFromEnum(linux.E.NOENT))));
    try testing.expectEqual(error.NoSuchDevice, errnoToError(-@as(i32, @intFromEnum(linux.E.NODEV))));
    try testing.expectEqual(error.InvalidRequest, errnoToError(-@as(i32, @intFromEnum(linux.E.INVAL))));
    try testing.expectEqual(error.NotSupported, errnoToError(-@as(i32, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expectEqual(error.SystemResources, errnoToError(-@as(i32, @intFromEnum(linux.E.NOBUFS))));
    try testing.expectEqual(error.Unexpected, errnoToError(-9999));
    try testing.expectEqual(error.Unexpected, errnoToError(0));
    try testing.expectEqual(error.Unexpected, errnoToError(std.math.minInt(i32)));
}

test "fuzz: parseQdisc never crashes on arbitrary payloads" {
    try testing.fuzz({}, fuzzParseQdisc, .{});
}

fn fuzzParseQdisc(_: void, smith: *std.testing.Smith) !void {
    var raw: [256]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    if (parseQdisc(raw[0..len])) |_| {} else |_| {}
}

// ── integration tests (real kernel, live netns round-trip) ──────────────────
//
// Both write ops (add/change/del) need CAP_NET_ADMIN; `show` does not. Run
// unprivileged under a network namespace to touch no host state:
//
//     unshare -rn zig build test-tc
//
// Without the capability, `Socket.add`/`.change`/`.del` return
// error.AccessDenied and the test returns error.SkipZigTest — the repo's
// env-gated pattern (see `netlink`/`wireguard`/`rawsock`).

fn openOrSkip() !Socket {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    return Socket.open(testing.allocator) catch return error.SkipZigTest;
}

test "integration: show() on lo needs no privilege and reports a qdisc" {
    var sock = try openOrSkip();
    defer sock.close();
    var nl = netlink.Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer nl.close();
    const links = nl.links() catch return error.SkipZigTest;
    defer testing.allocator.free(links);
    const lo = for (links) |l| {
        if (std.mem.eql(u8, l.name(), "lo")) break l.index;
    } else return error.SkipZigTest;

    const q = (sock.show(lo) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest,
        else => return e,
    }) orelse return error.SkipZigTest;
    try testing.expectEqual(lo, q.ifindex);
    try testing.expect(q.kind().len > 0); // "noqueue" by default on lo
}

test "integration (netns/root): add + show + change + show + del + show round-trip on lo" {
    var sock = try openOrSkip();
    defer sock.close();
    var nl = netlink.Socket.open(testing.allocator) catch return error.SkipZigTest;
    defer nl.close();
    const links = nl.links() catch return error.SkipZigTest;
    defer testing.allocator.free(links);
    const lo = for (links) |l| {
        if (std.mem.eql(u8, l.name(), "lo")) break l.index;
    } else return error.SkipZigTest;

    // Best-effort cleanup in case a previous aborted run left a qdisc
    // attached (harmless if there is none: del maps ENOENT to NotFound).
    sock.del(lo) catch {};

    const netem1: Netem = .{
        .delay_ns = 100 * std.time.ns_per_ms,
        .jitter_ns = 10 * std.time.ns_per_ms,
        .loss_pct = 1.0,
    };
    sock.add(lo, netem1) catch |e| switch (e) {
        error.AccessDenied => return error.SkipZigTest, // no CAP_NET_ADMIN
        else => return e,
    };
    defer sock.del(lo) catch {};

    {
        const q = (try sock.show(lo)).?;
        try testing.expectEqualStrings("netem", q.kind());
        const nw = q.netem.?;
        try testing.expectEqual(@as(i64, 100 * std.time.ns_per_ms), nw.delay_ns);
        try testing.expectEqual(@as(i64, 10 * std.time.ns_per_ms), nw.jitter_ns);
        try testing.expectEqual(try percentToU32(1.0), nw.loss);
    }

    // change(): replace with a different config, still root, still netem.
    const netem2: Netem = .{ .delay_ns = 20 * std.time.ns_per_ms, .duplicate_pct = 5.0 };
    try sock.change(lo, netem2);
    {
        const q = (try sock.show(lo)).?;
        try testing.expectEqualStrings("netem", q.kind());
        const nw = q.netem.?;
        try testing.expectEqual(@as(i64, 20 * std.time.ns_per_ms), nw.delay_ns);
        try testing.expectEqual(@as(i64, 0), nw.jitter_ns); // netem2 has none
        try testing.expectEqual(try percentToU32(5.0), nw.duplicate);
        try testing.expectEqual(@as(u32, 0), nw.loss); // netem2 has none
    }

    // del(): back to whatever default qdisc the kernel assigns lo.
    try sock.del(lo);
    {
        const q = (try sock.show(lo)).?;
        try testing.expect(!std.mem.eql(u8, q.kind(), "netem"));
    }
}

test {
    // dark-tests aggregator: this file is the whole module (single
    // src/root.zig), so nothing else to pull in.
}
