// SPDX-License-Identifier: MIT
//! Scanning: building `NL80211_CMD_TRIGGER_SCAN` requests and decoding the
//! `NL80211_ATTR_BSS` nests that `NL80211_CMD_GET_SCAN` dumps back.
//!
//! ## The scan is asynchronous, and this module says so
//!
//! `TRIGGER_SCAN` returns an ACK meaning *"the scan was started"*, nothing
//! more. Results are not in the reply; they land in the kernel's per-wiphy BSS
//! table some seconds later, and the completion is announced as a **multicast
//! event** (`NEW_SCAN_RESULTS` or `SCAN_ABORTED`) on the `scan` group. The
//! correct sequence is therefore:
//!
//! 1. subscribe to the `scan` group **before** triggering (otherwise the event
//!    can fire between the trigger and the subscription and be lost),
//! 2. `triggerScan`,
//! 3. block in the caller's own loop on the event socket,
//! 4. `GET_SCAN` dump.
//!
//! `client.zig` exposes exactly that shape; nothing here starts a thread or
//! owns a timer.
//!
//! ## Request encoding notes, from real `iw` traffic
//!
//! * `SCAN_SSIDS` is a nest whose entries are **indexed from 1**, each entry a
//!   raw (unterminated, unpadded-length) SSID. A single zero-length entry is
//!   the wildcard probe every ordinary scan sends. Omitting the nest entirely
//!   makes the scan passive.
//! * `SCAN_FREQUENCIES` is likewise indexed from 1, each entry a u32 MHz.
//!   Omitting it scans every supported channel.
//! * Neither nest carries `NLA_F_NESTED` on the wire — `iw` does not set it and
//!   the kernel's policy does not check it.
//! * The number of SSIDs is capped by the radio's `MAX_NUM_SCAN_SSIDS`; going
//!   over is EINVAL from the kernel, so the builder takes the cap as an
//!   argument and rejects locally with a named error instead.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const genl = @import("genetlink");
const uapi = @import("uapi.zig");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");
const ie = @import("ie.zig");

pub const BuildError = error{ OutOfMemory, InvalidRequest };
pub const ParseError = codec.Error || error{OutOfMemory};

// ── TRIGGER_SCAN ───────────────────────────────────────────────────────────

/// What to scan for.
pub const TriggerOptions = struct {
    ifindex: u32,
    /// SSIDs to probe for actively. An entry may be empty (the wildcard).
    /// Leaving this empty makes the scan **passive** — set it to
    /// `&.{""}` (one empty SSID) for the ordinary active scan `iw` performs.
    ssids: []const []const u8 = &.{},
    /// Restrict the scan to these channels (MHz). Empty = all channels.
    freqs_mhz: []const u32 = &.{},
    /// `NL80211_ATTR_SCAN_FLAGS` bits, e.g. `SCAN_FLAG.FLUSH`.
    flags: u32 = 0,
    /// Extra information elements to append to probe requests.
    ie_bytes: []const u8 = &.{},
    /// Reject locally when `ssids.len` exceeds the radio's advertised
    /// `MAX_NUM_SCAN_SSIDS`. Null = do not check (the kernel still will).
    max_num_ssids: ?u8 = null,
};

/// The wildcard SSID list an ordinary active scan uses.
pub const wildcard_ssids: []const []const u8 = &.{""};

/// Build a complete `NL80211_CMD_TRIGGER_SCAN` request. Caller frees.
pub fn buildTriggerScan(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    opts: TriggerOptions,
) BuildError![]u8 {
    if (opts.max_num_ssids) |cap| {
        if (opts.ssids.len > cap) return error.InvalidRequest;
    }
    for (opts.ssids) |s| {
        if (s.len > uapi.max_ssid_len) return error.InvalidRequest;
    }

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        family_id,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK,
        seq,
        0,
    );
    try genl.appendHeader(gpa, &list, uapi.CMD.TRIGGER_SCAN, uapi.family_version);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, opts.ifindex);

    if (opts.ssids.len != 0) {
        const nest = try codec.nestBegin(gpa, &list, uapi.ATTR.SCAN_SSIDS);
        for (opts.ssids, 1..) |s, i| {
            if (i > std.math.maxInt(u16)) return error.InvalidRequest;
            codec.appendAttr(gpa, &list, @intCast(i), s) catch |e| switch (e) {
                error.AttrTooLong => return error.InvalidRequest,
                error.OutOfMemory => return error.OutOfMemory,
            };
        }
        codec.nestEnd(&list, nest) catch return error.InvalidRequest;
    }
    if (opts.freqs_mhz.len != 0) {
        const nest = try codec.nestBegin(gpa, &list, uapi.ATTR.SCAN_FREQUENCIES);
        for (opts.freqs_mhz, 1..) |f, i| {
            if (i > std.math.maxInt(u16)) return error.InvalidRequest;
            try codec.appendAttrU32(gpa, &list, @intCast(i), f);
        }
        codec.nestEnd(&list, nest) catch return error.InvalidRequest;
    }
    if (opts.ie_bytes.len != 0) {
        codec.appendAttr(gpa, &list, uapi.ATTR.IE, opts.ie_bytes) catch |e| switch (e) {
            error.AttrTooLong => return error.InvalidRequest,
            error.OutOfMemory => return error.OutOfMemory,
        };
    }
    if (opts.flags != 0)
        try codec.appendAttrU32(gpa, &list, uapi.ATTR.SCAN_FLAGS, opts.flags);

    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

/// Build a `NL80211_CMD_GET_SCAN` dump request for one interface.
pub fn buildGetScan(
    gpa: std.mem.Allocator,
    family_id: u16,
    seq: u32,
    ifindex: u32,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    const hdr = try codec.appendHeader(
        gpa,
        &list,
        family_id,
        codec.NLM_F_REQUEST | codec.NLM_F_ACK | codec.NLM_F_DUMP,
        seq,
        0,
    );
    try genl.appendHeader(gpa, &list, uapi.CMD.GET_SCAN, uapi.family_version);
    try codec.appendAttrU32(gpa, &list, uapi.ATTR.IFINDEX, ifindex);
    codec.finishHeader(&list, hdr);
    return list.toOwnedSlice(gpa);
}

// ── BSS decoding ───────────────────────────────────────────────────────────

/// One BSS from the kernel's scan table.
///
/// `ies` and `beacon_ies` are **owned copies** of the raw information-element
/// streams, not borrows of the receive buffer: a `Bss` outlives the datagram
/// it came from, and the receive buffer is reused (and reallocated) by the
/// very next `recvmsg`. Free with `deinit`, or free a whole list with
/// `freeAll`.
pub const Bss = struct {
    bssid: ?uapi.Mac = null,
    /// Channel centre frequency, MHz.
    freq_mhz: ?u32 = null,
    /// Kilohertz offset from `freq_mhz` (6 GHz).
    freq_offset_khz: u32 = 0,
    /// Received signal, mBm (100 · dBm). -8000 = -80 dBm.
    signal_mbm: ?i32 = null,
    /// Unspecified-unit signal, 0..100, for drivers that report no dBm.
    signal_unspec: ?u8 = null,
    /// The 802.11 Capability Information field from the beacon/probe response.
    capability: ?u16 = null,
    /// Association state of *this* station with this BSS, when any.
    status: ?uapi.BssStatus = null,
    /// Age of the entry.
    seen_ms_ago: ?u32 = null,
    beacon_interval_tu: ?u16 = null,
    tsf: ?u64 = null,
    beacon_tsf: ?u64 = null,
    last_seen_boottime_ns: ?u64 = null,
    chan_width: ?uapi.ChanWidth = null,
    /// True when `ies` came from a probe response rather than a beacon.
    presp_data: bool = false,

    /// Information elements as received (probe response when `presp_data`,
    /// otherwise beacon). Owned.
    ies: []u8 = &.{},
    /// Beacon IEs when the kernel reported them separately. Owned.
    beacon_ies: []u8 = &.{},

    /// Signal in whole dBm, when the driver reported mBm.
    pub fn signalDbm(b: Bss) ?i32 {
        const mbm = b.signal_mbm orelse return null;
        return @divTrunc(mbm, 100);
    }

    /// Decode the elements — SSID, rates, channel, RSN. See `ie.Summary`.
    /// Prefers `ies`, falling back to `beacon_ies`.
    pub fn elements(b: Bss) ie.Summary {
        return ie.summarize(if (b.ies.len != 0) b.ies else b.beacon_ies);
    }

    /// The SSID from the information elements, or an empty slice. Verbatim
    /// bytes — never print unescaped.
    pub fn ssid(b: Bss) []const u8 {
        return b.elements().ssid;
    }

    pub fn deinit(b: *Bss, gpa: std.mem.Allocator) void {
        gpa.free(b.ies);
        gpa.free(b.beacon_ies);
        b.* = undefined;
    }
};

/// Free a list of BSSes.
pub fn freeAll(gpa: std.mem.Allocator, list: []Bss) void {
    for (list) |*b| b.deinit(gpa);
    gpa.free(list);
}

/// Decode one `NL80211_CMD_NEW_SCAN_RESULTS` message's attribute bytes into a
/// `Bss`, or null when the message carried no `NL80211_ATTR_BSS`.
pub fn parseBss(gpa: std.mem.Allocator, attr_bytes: []const u8) ParseError!?Bss {
    var it: codec.AttrIterator = .{ .buf = attr_bytes };
    while (try it.next()) |a| {
        if (a.type != uapi.ATTR.BSS) continue;
        return try parseBssNest(gpa, a.data);
    }
    return null;
}

/// Decode a bare `NL80211_ATTR_BSS` nest.
pub fn parseBssNest(gpa: std.mem.Allocator, nest: []const u8) ParseError!Bss {
    var b: Bss = .{};
    errdefer b.deinit(gpa);
    var it: codec.AttrIterator = .{ .buf = nest };
    while (try it.next()) |a| switch (a.type) {
        uapi.BSS.BSSID => {
            if (a.data.len != 6) return error.BadLength;
            b.bssid = a.data[0..6].*;
        },
        uapi.BSS.FREQUENCY => b.freq_mhz = try a.asU32(),
        uapi.BSS.FREQUENCY_OFFSET => b.freq_offset_khz = try a.asU32(),
        uapi.BSS.SIGNAL_MBM => b.signal_mbm = try a.asI32(),
        uapi.BSS.SIGNAL_UNSPEC => b.signal_unspec = try a.asU8(),
        uapi.BSS.CAPABILITY => b.capability = try a.asU16(),
        uapi.BSS.STATUS => b.status = @enumFromInt(try a.asU32()),
        uapi.BSS.SEEN_MS_AGO => b.seen_ms_ago = try a.asU32(),
        uapi.BSS.BEACON_INTERVAL => b.beacon_interval_tu = try a.asU16(),
        uapi.BSS.CHAN_WIDTH => b.chan_width = @enumFromInt(try a.asU32()),
        uapi.BSS.PRESP_DATA => b.presp_data = true,
        uapi.BSS.TSF => b.tsf = try asU64(a),
        uapi.BSS.BEACON_TSF => b.beacon_tsf = try asU64(a),
        uapi.BSS.LAST_SEEN_BOOTTIME => b.last_seen_boottime_ns = try asU64(a),
        uapi.BSS.INFORMATION_ELEMENTS => {
            // A repeated attribute would leak the first copy.
            if (b.ies.len != 0) return error.BadLength;
            b.ies = try gpa.dupe(u8, a.data);
        },
        uapi.BSS.BEACON_IES => {
            if (b.beacon_ies.len != 0) return error.BadLength;
            b.beacon_ies = try gpa.dupe(u8, a.data);
        },
        else => {},
    };
    return b;
}

fn asU64(a: codec.Attr) codec.Error!u64 {
    if (a.data.len != 8) return error.BadLength;
    return std.mem.readInt(u64, a.data[0..8], .little);
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

test "buildTriggerScan rejects requests the kernel would EINVAL" {
    const gpa = testing.allocator;
    // More SSIDs than the radio allows.
    try testing.expectError(error.InvalidRequest, buildTriggerScan(gpa, 41, 1, .{
        .ifindex = 3,
        .ssids = &.{ "a", "b", "c" },
        .max_num_ssids = 2,
    }));
    // An SSID over the 802.11 ceiling.
    const too_long: [33]u8 = @splat('x');
    try testing.expectError(error.InvalidRequest, buildTriggerScan(gpa, 41, 1, .{
        .ifindex = 3,
        .ssids = &.{&too_long},
    }));
    // Exactly at the cap is fine.
    const ok = try buildTriggerScan(gpa, 41, 1, .{
        .ifindex = 3,
        .ssids = &.{ "a", "b" },
        .max_num_ssids = 2,
    });
    gpa.free(ok);
}

test "buildTriggerScan: a passive scan omits the SSID nest entirely" {
    const gpa = testing.allocator;
    const req = try buildTriggerScan(gpa, 41, 7, .{ .ifindex = 3 });
    defer gpa.free(req);
    var it: codec.MessageIterator = .{ .buf = req };
    const m = (try it.next()).?;
    var attrs: codec.AttrIterator = .{ .buf = m.payload[genl.header_len..] };
    var saw_ssids = false;
    while (try attrs.next()) |a| {
        if (a.type == uapi.ATTR.SCAN_SSIDS) saw_ssids = true;
    }
    try testing.expect(!saw_ssids);
}

test "buildTriggerScan: SSID and frequency nests are indexed from 1" {
    const gpa = testing.allocator;
    const req = try buildTriggerScan(gpa, 41, 7, .{
        .ifindex = 3,
        .ssids = &.{ "one", "two" },
        .freqs_mhz = &.{ 2412, 2437 },
    });
    defer gpa.free(req);

    var it: codec.MessageIterator = .{ .buf = req };
    const m = (try it.next()).?;
    var attrs: codec.AttrIterator = .{ .buf = m.payload[genl.header_len..] };
    var ssid_indices: [2]u16 = @splat(0);
    var freq_indices: [2]u16 = @splat(0);
    var n_ssid: usize = 0;
    var n_freq: usize = 0;
    while (try attrs.next()) |a| switch (a.type) {
        uapi.ATTR.SCAN_SSIDS => {
            var inner = a.nested();
            while (try inner.next()) |s| : (n_ssid += 1) ssid_indices[n_ssid] = s.type;
        },
        uapi.ATTR.SCAN_FREQUENCIES => {
            var inner = a.nested();
            while (try inner.next()) |f| : (n_freq += 1) freq_indices[n_freq] = f.type;
        },
        else => {},
    };
    try testing.expectEqualSlices(u16, &.{ 1, 2 }, &ssid_indices);
    try testing.expectEqualSlices(u16, &.{ 1, 2 }, &freq_indices);
}

test "parseBss: a hand-built nest round-trips through the decoder" {
    const gpa = testing.allocator;
    var nest: std.ArrayList(u8) = .empty;
    defer nest.deinit(gpa);
    try codec.appendAttr(gpa, &nest, uapi.BSS.BSSID, &.{ 0x02, 0, 0, 0xaa, 0xbb, 0xcc });
    try codec.appendAttrU32(gpa, &nest, uapi.BSS.FREQUENCY, 5500);
    try codec.appendAttrU32(gpa, &nest, uapi.BSS.SIGNAL_MBM, @bitCast(@as(i32, -8100)));
    try codec.appendAttrU16(gpa, &nest, uapi.BSS.CAPABILITY, 0x1111);
    try codec.appendAttrU16(gpa, &nest, uapi.BSS.BEACON_INTERVAL, 100);
    try codec.appendAttrU32(gpa, &nest, uapi.BSS.STATUS, 1);
    try codec.appendAttrU32(gpa, &nest, uapi.BSS.SEEN_MS_AGO, 10240);
    try codec.appendAttr(gpa, &nest, uapi.BSS.INFORMATION_ELEMENTS, &.{ 0, 3, 'a', 'p', '1', 3, 1, 6 });

    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    const off = try codec.nestBegin(gpa, &msg, uapi.ATTR.BSS);
    try msg.appendSlice(gpa, nest.items);
    codec.nestEnd(&msg, off) catch return error.InvalidRequest;

    var b = (try parseBss(gpa, msg.items)).?;
    defer b.deinit(gpa);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0, 0, 0xaa, 0xbb, 0xcc }, &b.bssid.?);
    try testing.expectEqual(@as(?u32, 5500), b.freq_mhz);
    try testing.expectEqual(@as(?i32, -81), b.signalDbm());
    try testing.expectEqual(@as(?u16, 0x1111), b.capability);
    try testing.expectEqual(uapi.BssStatus.associated, b.status.?);
    try testing.expectEqual(@as(?u32, 10240), b.seen_ms_ago);
    try testing.expectEqualStrings("ap1", b.ssid());
    try testing.expectEqual(@as(?u8, 6), b.elements().ds_channel);
}

test "parseBss on a message without an ATTR_BSS yields null" {
    const gpa = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(gpa);
    try codec.appendAttrU32(gpa, &msg, uapi.ATTR.IFINDEX, 3);
    try testing.expectEqual(@as(?Bss, null), try parseBss(gpa, msg.items));
}

test "parseBss: malformed nests error out without leaking the IE copy" {
    const gpa = testing.allocator;
    // IE attribute present twice — the second must not orphan the first.
    var nest: std.ArrayList(u8) = .empty;
    defer nest.deinit(gpa);
    try codec.appendAttr(gpa, &nest, uapi.BSS.INFORMATION_ELEMENTS, &.{ 0, 1, 'a' });
    try codec.appendAttr(gpa, &nest, uapi.BSS.INFORMATION_ELEMENTS, &.{ 0, 1, 'b' });
    try testing.expectError(error.BadLength, parseBssNest(gpa, nest.items));

    // BSSID of the wrong width, after an IE copy has already been made.
    var nest2: std.ArrayList(u8) = .empty;
    defer nest2.deinit(gpa);
    try codec.appendAttr(gpa, &nest2, uapi.BSS.INFORMATION_ELEMENTS, &.{ 0, 1, 'a' });
    try codec.appendAttr(gpa, &nest2, uapi.BSS.BSSID, &.{ 1, 2, 3 });
    try testing.expectError(error.BadLength, parseBssNest(gpa, nest2.items));

    // Truncated TLV inside the nest.
    try testing.expectError(error.Truncated, parseBssNest(gpa, &.{ 0x40, 0x00, 0x01, 0x00, 0xff }));
}

test "parseBss: elements() falls back to the beacon IEs" {
    const gpa = testing.allocator;
    var nest: std.ArrayList(u8) = .empty;
    defer nest.deinit(gpa);
    try codec.appendAttr(gpa, &nest, uapi.BSS.BEACON_IES, &.{ 0, 2, 'h', 'i' });
    var b = try parseBssNest(gpa, nest.items);
    defer b.deinit(gpa);
    try testing.expectEqualStrings("hi", b.ssid());
}

/// GET_SCAN reply attribute lists and bare BSS nests for `fuzzParse`, in the format `Smith.slice` reads (see
/// `testkit.fuzz`): a little-endian u32 length, then the frame.
///
/// ⭐ Built at run time by `codec`'s own encoders, the way the value tests
/// above build theirs, rather than quoted as hex: an nl80211 attribute is a
/// netlink TLV, whose length and scalars are HOST byte order, so a hex corpus
/// would be a little-endian one and the counts pinned below would be false on
/// a big-endian target instead of failing there.
const Corpus = struct {
    scratch: [8192]u8 = undefined,
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *Corpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *Corpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // A whole BSS nest inside an ATTR.BSS wrapper: what `parseBss` takes.
        var nest: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &nest, uapi.BSS.BSSID, &.{ 0x02, 0, 0, 0xaa, 0xbb, 0xcc });
        try codec.appendAttrU32(gpa, &nest, uapi.BSS.FREQUENCY, 5500);
        try codec.appendAttrU32(gpa, &nest, uapi.BSS.SIGNAL_MBM, @bitCast(@as(i32, -8100)));
        try codec.appendAttrU16(gpa, &nest, uapi.BSS.CAPABILITY, 0x1111);
        try codec.appendAttrU16(gpa, &nest, uapi.BSS.BEACON_INTERVAL, 100);
        try codec.appendAttrU32(gpa, &nest, uapi.BSS.STATUS, 1);
        try codec.appendAttrU32(gpa, &nest, uapi.BSS.SEEN_MS_AGO, 10240);
        try codec.appendAttr(gpa, &nest, uapi.BSS.INFORMATION_ELEMENTS, &.{ 0, 3, 'a', 'p', '1', 3, 1, 6 });
        var wrapped: std.ArrayList(u8) = .empty;
        {
            const off = try codec.nestBegin(gpa, &wrapped, uapi.ATTR.BSS);
            try wrapped.appendSlice(gpa, nest.items);
            try codec.nestEnd(&wrapped, off);
        }
        self.push(wrapped.items);
        // The same nest bare, which is what `parseBssNest` takes.
        self.push(nest.items);

        // Beacon IEs only: the fallback path in `elements()`.
        var beacon: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &beacon, uapi.BSS.BEACON_IES, &.{ 0, 2, 'h', 'i' });
        self.push(beacon.items);

        // ── the refusals ───────────────────────────────────────────────────
        // The IE attribute twice: the second must not orphan the first copy.
        var twice: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &twice, uapi.BSS.INFORMATION_ELEMENTS, &.{ 0, 1, 'a' });
        try codec.appendAttr(gpa, &twice, uapi.BSS.INFORMATION_ELEMENTS, &.{ 0, 1, 'b' });
        self.push(twice.items);
        // A BSSID of the wrong width, after an IE copy has already been made.
        var after_copy: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &after_copy, uapi.BSS.INFORMATION_ELEMENTS, &.{ 0, 1, 'a' });
        try codec.appendAttr(gpa, &after_copy, uapi.BSS.BSSID, &.{ 1, 2, 3 });
        self.push(after_copy.items);
        // A truncated TLV inside the nest.
        self.push(&[_]u8{ 0x40, 0x00, 0x01, 0x00, 0xff });

        return self.entries[0..self.n];
    }
};

test "fuzz: BSS parsing never crashes or leaks" {
    var corpus: Corpus = .{};
    try testing.fuzz({}, fuzzParse, .{ .corpus = try corpus.build() });
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and both `parseBss` and `parseBssNest` were handed an empty attribute list, with
    // the reply sitting unread in `raw`.
    //
    // ⛔ And it looked HEALTHIER that way: an empty nest is a
    // legal BSS with every field absent, so `parseBssNest("")` succeeded every
    // round. Measured 2026-09-07 over the corpus above: **0 of 6 seeds
    // non-empty, 6 of 6 nests "parsed" and 0 BSSes found through the ATTR.BSS
    // wrapper before; 6 of 6 non-empty, 3 nests parsed and 1 BSS found
    // after.**
    const len: usize = smith.slice(&raw);
    if (parseBss(testing.allocator, raw[0..len])) |maybe| {
        if (maybe) |bss| {
            var b = bss;
            b.deinit(testing.allocator);
        }
    } else |_| {}
    if (parseBssNest(testing.allocator, raw[0..len])) |bss| {
        var b = bss;
        b.deinit(testing.allocator);
    } else |_| {}
}

test "corpus: every scan seed reaches both parsers, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The second number
    // is what the first cannot say: an empty attribute list is a legal reply
    // here, so "parsed" alone counts a harness that walks nothing as a
    // success.
    var corpus: Corpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var nests: usize = 0;
    var found: usize = 0;
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [512]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        if (parseBss(testing.allocator, raw[0..len])) |maybe| {
            if (maybe) |bss| {
                found += 1;
                var b = bss;
                b.deinit(testing.allocator);
            }
        } else |_| {}
        if (parseBssNest(testing.allocator, raw[0..len])) |bss| {
            nests += 1;
            var b = bss;
            b.deinit(testing.allocator);
        } else |_| {}
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 3), nests);
    try testing.expectEqual(@as(usize, 1), found);
}
