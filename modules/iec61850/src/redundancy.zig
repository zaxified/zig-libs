// SPDX-License-Identifier: MIT

//! **PRP and HSR duplicate discard** (IEC 62439-3) for a GOOSE or sampled-value
//! subscriber on a redundant station bus.
//!
//! A node attached to a PRP network sends every frame twice, once on each of two
//! independent LANs, and a node on an HSR ring sends it twice round the ring. A
//! subscriber therefore sees every frame two times. The second copy is not a
//! retransmission, it carries the same `sqNum`, and a `Subscriber` that is fed
//! both reports a refresh that never was — or, worse, an out-of-order frame — for
//! every GOOSE. This file is the filter that sits in front of the decoder:
//!
//! * **PRP** appends a six-octet *Redundancy Control Trailer* to the frame:
//!   `SeqNr (16)`, `LanId (4) | LSDUsize (12)`, `Suffix 0x88FB (16)`. The GOOSE
//!   decoder already ignores octets after the PDU, so the frame passes unchanged
//!   (the filter hands back the frame without the trailer).
//! * **HSR** inserts a *tag* in front of the payload: EtherType `0x892F`,
//!   `Path (4) | LSDUsize (12)`, `SeqNr (16)`, and then the encapsulated
//!   EtherType. The frame is rewritten into the plain one (the tag removed) in a
//!   caller-supplied buffer.
//!
//! In both, the receiver keeps, for each **source MAC**, a window of the sequence
//! numbers it has recently accepted and drops a frame whose number is in it. The
//! counter belongs to the *node*, not to the control block: all of a source's
//! streams share it.
//!
//! The table is bounded (`max_sources`, no allocator) and entries are forgotten
//! after `forget_ms`, which is what makes a publisher that restarts (and so
//! restarts its sequence numbers) audible again. A frame with neither a trailer
//! nor a tag comes from a node that is not redundant (a SAN on the bus) and passes
//! through, counted as `untagged`.
//!
//! No clock, no socket: `accept` takes `now_ms`.

const std = @import("std");

pub const Error = error{
    /// Shorter than an Ethernet header.
    ShortFrame,
    /// `out` cannot hold the rewritten HSR frame.
    BufferTooSmall,
};

pub const prp_suffix: u16 = 0x88FB;
pub const hsr_ether_type: u16 = 0x892F;
const vlan_ether_type: u16 = 0x8100;

/// Sources tracked at once. A GOOSE bus has a handful of publishers; the oldest
/// entry is evicted when a source past the bound turns up.
pub const max_sources: usize = 64;

/// PRP's `EntryForgetTime` (IEC 62439-3) is 400 ms.
pub const default_forget_ms: u32 = 400;

/// Which of the two PRP networks a frame travelled.
pub const Lan = enum {
    a,
    b,

    pub fn id(self: Lan) u4 {
        return switch (self) {
            .a => 0xA,
            .b => 0xB,
        };
    }
};

/// The PRP Redundancy Control Trailer.
pub const Rct = struct {
    seq: u16,
    lan: Lan,
    /// Octets of the LSDU (the Ethernet payload), the trailer included.
    lsdu_size: u12,
};

/// The HSR tag.
pub const HsrTag = struct {
    path: u4,
    /// As sent. Not validated on receive: no third-party HSR peer was available
    /// to confirm exactly which octets it counts.
    lsdu_size: u12,
    seq: u16,
};

/// Octets of Ethernet header: 14, or 18 with an 802.1Q tag.
fn headerLen(frame: []const u8) ?usize {
    if (frame.len < 14) return null;
    if (std.mem.readInt(u16, frame[12..14], .big) == vlan_ether_type) {
        return if (frame.len < 18) null else 18;
    }
    return 14;
}

/// The trailer of a PRP frame, or null when the frame does not end in a valid one.
/// Validity: the suffix, a LAN id of `A` or `B`, and an LSDU size that is at least
/// the trailer and at most the payload (a padded frame is longer than it says).
pub fn parseRct(frame: []const u8) ?Rct {
    const hdr = headerLen(frame) orelse return null;
    if (frame.len < hdr + 6) return null;
    const t = frame[frame.len - 6 ..];
    if (std.mem.readInt(u16, t[4..6], .big) != prp_suffix) return null;
    const lan_size = std.mem.readInt(u16, t[2..4], .big);
    const lan: Lan = switch (lan_size >> 12) {
        0xA => .a,
        0xB => .b,
        else => return null,
    };
    const size: u12 = @truncate(lan_size);
    if (size < 6 or size > frame.len - hdr) return null;
    return .{ .seq = std.mem.readInt(u16, t[0..2], .big), .lan = lan, .lsdu_size = size };
}

/// Appends a PRP trailer to the `len` octets of frame already in `out`, and
/// returns the new length. The caller pads a short frame to the Ethernet minimum
/// *before* this if it wants the trailer after the padding, as the standard has it.
pub fn appendRct(out: []u8, len: usize, seq: u16, lan: Lan) Error!usize {
    const hdr = headerLen(out[0..len]) orelse return error.ShortFrame;
    if (out.len < len + 6) return error.BufferTooSmall;
    const size: u16 = @intCast(@min(len - hdr + 6, 0xFFF));
    std.mem.writeInt(u16, out[len..][0..2], seq, .big);
    std.mem.writeInt(u16, out[len + 2 ..][0..2], (@as(u16, lan.id()) << 12) | size, .big);
    std.mem.writeInt(u16, out[len + 4 ..][0..2], prp_suffix, .big);
    return len + 6;
}

/// Where the EtherType sits in a frame (12, or 16 behind an 802.1Q tag).
fn etherTypeOffset(frame: []const u8) ?usize {
    const hdr = headerLen(frame) orelse return null;
    return hdr - 2;
}

/// The HSR tag of a frame, or null when the EtherType is not `0x892F` or the tag
/// is cut short.
pub fn parseHsr(frame: []const u8) ?HsrTag {
    const et = etherTypeOffset(frame) orelse return null;
    if (frame.len < et + 8) return null;
    if (std.mem.readInt(u16, frame[et..][0..2], .big) != hsr_ether_type) return null;
    const ps = std.mem.readInt(u16, frame[et + 2 ..][0..2], .big);
    return .{
        .path = @truncate(ps >> 12),
        .lsdu_size = @truncate(ps),
        .seq = std.mem.readInt(u16, frame[et + 4 ..][0..2], .big),
    };
}

/// Inserts an HSR tag into a plain frame, writing the result to `out`. The size
/// field counts the octets from the encapsulated EtherType to the end.
pub fn encodeHsr(plain: []const u8, path: u4, seq: u16, out: []u8) Error![]u8 {
    const et = etherTypeOffset(plain) orelse return error.ShortFrame;
    if (plain.len < et + 2) return error.ShortFrame;
    if (out.len < plain.len + 6) return error.BufferTooSmall;
    @memcpy(out[0..et], plain[0..et]);
    std.mem.writeInt(u16, out[et..][0..2], hsr_ether_type, .big);
    const size: u16 = @intCast(@min(plain.len - et, 0xFFF));
    std.mem.writeInt(u16, out[et + 2 ..][0..2], (@as(u16, path) << 12) | size, .big);
    std.mem.writeInt(u16, out[et + 4 ..][0..2], seq, .big);
    @memcpy(out[et + 6 ..][0 .. plain.len - et], plain[et..]);
    return out[0 .. plain.len + 6];
}

/// Removes the HSR tag from `frame` into `out`; the plain frame is what
/// `goose.Frame.decode` reads.
pub fn stripHsr(frame: []const u8, out: []u8) Error![]u8 {
    const et = etherTypeOffset(frame) orelse return error.ShortFrame;
    if (frame.len < et + 8) return error.ShortFrame;
    const n = frame.len - 6;
    if (out.len < n) return error.BufferTooSmall;
    @memcpy(out[0..et], frame[0..et]);
    @memcpy(out[et..n], frame[et + 6 ..]);
    return out[0..n];
}

pub const Mode = enum {
    /// Look for an HSR tag, then for a PRP trailer.
    auto,
    prp,
    hsr,
};

pub const Config = struct {
    mode: Mode = .auto,
    /// How long a source's window is kept without a new frame from it; 0 never
    /// forgets (and so never lets a restarted publisher back in).
    forget_ms: u32 = default_forget_ms,
};

pub const Kind = enum { untagged, prp, hsr };

pub const Result = struct {
    kind: Kind,
    /// An already-seen copy: do not hand it to the subscriber.
    duplicate: bool,
    /// The frame's redundancy sequence number (0 when untagged).
    seq: u16 = 0,
    /// The LAN a PRP frame travelled.
    lan: ?Lan = null,
    /// The plain frame to decode: the input without its PRP trailer, the HSR
    /// frame rewritten into `out`, or the input itself when untagged.
    frame: []const u8,
};

pub const Stats = struct {
    accepted: u64 = 0,
    duplicates: u64 = 0,
    untagged: u64 = 0,
    /// Accepted PRP frames per LAN: a LAN that stops contributing first shows
    /// here, long before anything is lost.
    lan_a: u64 = 0,
    lan_b: u64 = 0,
};

const Entry = struct {
    used: bool = false,
    mac: [6]u8 = @splat(0),
    /// The newest accepted sequence number; bit `i` of `window` says whether
    /// `newest - i` has been seen.
    newest: u16 = 0,
    window: u64 = 0,
    last_ms: u64 = 0,
};

pub const Filter = struct {
    config: Config,
    entries: [max_sources]Entry = @splat(.{}),
    stats: Stats = .{},

    pub fn init(config: Config) Filter {
        return .{ .config = config };
    }

    /// Classifies one received frame and decides whether it is a duplicate.
    /// `out` is scratch for an HSR frame (it needs `frame.len - 6` octets) and is
    /// untouched otherwise.
    pub fn accept(self: *Filter, frame: []const u8, out: []u8, now_ms: u64) Error!Result {
        if (headerLen(frame) == null) return error.ShortFrame;
        const src: [6]u8 = frame[6..12].*;

        if (self.config.mode != .prp) {
            if (parseHsr(frame)) |tag| {
                const plain = try stripHsr(frame, out);
                const dup = self.seen(src, tag.seq, now_ms);
                self.count(dup, null);
                return .{ .kind = .hsr, .duplicate = dup, .seq = tag.seq, .frame = plain };
            }
        }
        if (self.config.mode != .hsr) {
            if (parseRct(frame)) |rct| {
                const dup = self.seen(src, rct.seq, now_ms);
                self.count(dup, rct.lan);
                return .{
                    .kind = .prp,
                    .duplicate = dup,
                    .seq = rct.seq,
                    .lan = rct.lan,
                    .frame = frame[0 .. frame.len - 6],
                };
            }
        }
        self.stats.untagged += 1;
        return .{ .kind = .untagged, .duplicate = false, .frame = frame };
    }

    fn count(self: *Filter, dup: bool, lan: ?Lan) void {
        if (dup) {
            self.stats.duplicates += 1;
            return;
        }
        self.stats.accepted += 1;
        if (lan) |l| switch (l) {
            .a => self.stats.lan_a += 1,
            .b => self.stats.lan_b += 1,
        };
    }

    /// Records `seq` from `mac` and says whether it had been recorded already.
    fn seen(self: *Filter, mac: [6]u8, seq: u16, now_ms: u64) bool {
        const e = self.entryFor(mac);
        const fresh = !e.used or
            (self.config.forget_ms != 0 and now_ms -| e.last_ms >= self.config.forget_ms);
        if (fresh) {
            e.* = .{ .used = true, .mac = mac, .newest = seq, .window = 1, .last_ms = now_ms };
            return false;
        }
        const diff: i16 = @bitCast(seq -% e.newest);
        if (diff == 0) return true;
        if (diff > 0) {
            const d: u16 = @intCast(diff);
            e.window = if (d >= 64) 0 else e.window << @intCast(d);
            e.window |= 1;
            e.newest = seq;
            e.last_ms = now_ms;
            return false;
        }
        const back: u32 = @intCast(-@as(i32, diff));
        if (back < 64) {
            const bit = @as(u64, 1) << @intCast(back);
            if (e.window & bit != 0) return true;
            e.window |= bit;
            e.last_ms = now_ms;
            return false;
        }
        // Further back than the window remembers: a publisher that restarted its
        // counter, not a late copy (copies arrive within milliseconds). Start over.
        e.newest = seq;
        e.window = 1;
        e.last_ms = now_ms;
        return false;
    }

    /// The entry of `mac`, a free one, or the least recently used (evicted). A
    /// returned entry that is not `used` is new.
    fn entryFor(self: *Filter, mac: [6]u8) *Entry {
        var free: ?*Entry = null;
        var oldest: *Entry = &self.entries[0];
        for (&self.entries) |*e| {
            if (!e.used) {
                if (free == null) free = e;
                continue;
            }
            if (std.mem.eql(u8, &e.mac, &mac)) return e;
            if (e.last_ms < oldest.last_ms or !oldest.used) oldest = e;
        }
        if (free) |f| return f;
        oldest.used = false;
        return oldest;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const goose = @import("goose.zig");
const mmsdata = @import("mmsdata.zig");

/// A GOOSE frame from `src` with the given sequence number, optionally 802.1Q-tagged.
fn gooseFrame(src: u8, sq: u32, vlan: bool, out: []u8) ![]u8 {
    const pdu = goose.Pdu{
        .gocb_ref = "IED1LD0/LLN0$GO$gcb",
        .time_allowed_to_live_ms = 2000,
        .dat_set = "IED1LD0/LLN0$DS",
        .go_id = "gcb",
        .t = mmsdata.UtcTime.fromMillis(1_700_000_000_000, null),
        .st_num = 1,
        .sq_num = sq,
        .test_mode = false,
        .conf_rev = 1,
        .nds_com = false,
        .num_dat_set_entries = 0,
        .all_data = "",
    };
    var pbuf: [256]u8 = undefined;
    const bytes = try pdu.encode(&.{}, &pbuf);
    const f = goose.Frame{
        .dst = .{ 0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01 },
        .src = .{ 0x00, 0x11, 0x22, 0x33, 0x44, src },
        .appid = 0x1000,
        .pdu = &.{},
        .total_len = 0,
        .vlan = if (vlan) .{ .priority = 4, .id = 5 } else null,
    };
    return f.encode(bytes, out);
}

test "PRP: the second copy of a frame is a duplicate, whichever LAN it came first on" {
    var fil = Filter.init(.{});
    var buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    for (0..2) |round| {
        const base: u16 = @intCast(round * 10);
        for (0..3) |i| {
            const seq: u16 = base + @as(u16, @intCast(i));
            var len = (try gooseFrame(1, seq, false, &buf)).len;
            // Alternate which LAN wins the race.
            const first: Lan = if (i % 2 == 0) .a else .b;
            const second: Lan = if (i % 2 == 0) .b else .a;
            var a = buf;
            len = try appendRct(&a, len, seq, first);
            const r1 = try fil.accept(a[0..len], &out, 1000 + seq);
            try testing.expect(!r1.duplicate);
            try testing.expectEqual(Kind.prp, r1.kind);
            try testing.expectEqual(first, r1.lan.?);
            var b = buf;
            const len2 = try appendRct(&b, len - 6, seq, second);
            const r2 = try fil.accept(b[0..len2], &out, 1001 + seq);
            try testing.expect(r2.duplicate);
            try testing.expectEqual(seq, r2.seq);
        }
    }
    try testing.expectEqual(@as(u64, 6), fil.stats.accepted);
    try testing.expectEqual(@as(u64, 6), fil.stats.duplicates);
    try testing.expectEqual(@as(u64, 4), fil.stats.lan_a);
    try testing.expectEqual(@as(u64, 2), fil.stats.lan_b);
}

test "PRP: the filtered frame still decodes as GOOSE, trailer gone" {
    var fil = Filter.init(.{});
    var buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    for ([_]bool{ false, true }) |tagged| {
        const plain = try gooseFrame(2, 7, tagged, &buf);
        const plain_len = plain.len;
        const len = try appendRct(&buf, plain_len, 40, .a);
        const r = try fil.accept(buf[0..len], &out, 5);
        try testing.expectEqual(plain_len, r.frame.len);
        const f = try goose.Frame.decode(r.frame);
        try testing.expectEqual(@as(u16, 0x1000), f.appid);
        try testing.expectEqual(@as(u32, 7), (try goose.Pdu.decode(f.pdu)).sq_num);
        try testing.expectEqual(tagged, f.vlan != null);
        fil = Filter.init(.{});
    }
}

test "HSR: the tag is stripped into a plain frame and the ring's second copy is dropped" {
    var fil = Filter.init(.{});
    var plain_buf: [512]u8 = undefined;
    var tagged: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    for ([_]bool{ false, true }) |vlan| {
        fil = Filter.init(.{});
        const plain = try gooseFrame(3, 9, vlan, &plain_buf);
        const t1 = try encodeHsr(plain, 0, 77, &tagged);
        try testing.expectEqual(plain.len + 6, t1.len);
        const tag = parseHsr(t1).?;
        try testing.expectEqual(@as(u16, 77), tag.seq);
        try testing.expectEqual(@as(u4, 0), tag.path);
        const r1 = try fil.accept(t1, &out, 100);
        try testing.expectEqual(Kind.hsr, r1.kind);
        try testing.expect(!r1.duplicate);
        try testing.expectEqualSlices(u8, plain, r1.frame);
        try testing.expectEqual(@as(u32, 9), (try goose.Pdu.decode((try goose.Frame.decode(r1.frame)).pdu)).sq_num);
        // The copy that went the other way round the ring.
        var other: [512]u8 = undefined;
        const t2 = try encodeHsr(plain, 1, 77, &other);
        const r2 = try fil.accept(t2, &out, 101);
        try testing.expect(r2.duplicate);
        // The next frame is new.
        const t3 = try encodeHsr(plain, 0, 78, &other);
        try testing.expect(!(try fil.accept(t3, &out, 102)).duplicate);
    }
}

test "sources do not share a counter, and late or reordered frames are judged by the window" {
    var fil = Filter.init(.{});
    var out: [64]u8 = undefined;
    var buf: [512]u8 = undefined;
    const frame = struct {
        fn f(b: *[512]u8, src: u8, seq: u16) ![]const u8 {
            const plain = try gooseFrame(src, 1, false, b);
            const n = try appendRct(b, plain.len, seq, .a);
            return b[0..n];
        }
    }.f;
    try testing.expect(!(try fil.accept(try frame(&buf, 1, 5), &out, 0)).duplicate);
    // The same number from another node is not a duplicate.
    try testing.expect(!(try fil.accept(try frame(&buf, 2, 5), &out, 0)).duplicate);
    // Reordered inside the window: new once, then a duplicate.
    try testing.expect(!(try fil.accept(try frame(&buf, 1, 9), &out, 0)).duplicate);
    try testing.expect(!(try fil.accept(try frame(&buf, 1, 7), &out, 0)).duplicate);
    try testing.expect((try fil.accept(try frame(&buf, 1, 7), &out, 0)).duplicate);
    try testing.expect((try fil.accept(try frame(&buf, 1, 9), &out, 0)).duplicate);
    try testing.expect((try fil.accept(try frame(&buf, 1, 5), &out, 0)).duplicate);
    // The counter wraps: 65535 then 0 then 1 are three new frames.
    try testing.expect(!(try fil.accept(try frame(&buf, 3, 65535), &out, 0)).duplicate);
    try testing.expect(!(try fil.accept(try frame(&buf, 3, 0), &out, 0)).duplicate);
    try testing.expect(!(try fil.accept(try frame(&buf, 3, 1), &out, 0)).duplicate);
    try testing.expect((try fil.accept(try frame(&buf, 3, 65535), &out, 0)).duplicate);
    // A jump forward past the window forgets what was behind it.
    try testing.expect(!(try fil.accept(try frame(&buf, 3, 200), &out, 0)).duplicate);
    try testing.expect(!(try fil.accept(try frame(&buf, 3, 1), &out, 0)).duplicate);
}

test "a publisher that restarts its counter is heard again, by forget time or by distance" {
    var fil = Filter.init(.{ .forget_ms = 400 });
    var out: [64]u8 = undefined;
    var buf: [512]u8 = undefined;
    const frame = struct {
        fn f(b: *[512]u8, seq: u16) ![]const u8 {
            const plain = try gooseFrame(1, 1, false, b);
            const n = try appendRct(b, plain.len, seq, .b);
            return b[0..n];
        }
    }.f;
    try testing.expect(!(try fil.accept(try frame(&buf, 3000), &out, 1000)).duplicate);
    // Restarted at 3000 again after a pause longer than the forget time.
    try testing.expect(!(try fil.accept(try frame(&buf, 3000), &out, 1500)).duplicate);
    // Restarted at a small number inside the forget time: far behind the window.
    try testing.expect(!(try fil.accept(try frame(&buf, 2), &out, 1600)).duplicate);
    try testing.expect((try fil.accept(try frame(&buf, 2), &out, 1601)).duplicate);
    // forget_ms = 0 never forgets.
    var keep = Filter.init(.{ .forget_ms = 0 });
    try testing.expect(!(try keep.accept(try frame(&buf, 50), &out, 0)).duplicate);
    try testing.expect((try keep.accept(try frame(&buf, 50), &out, 10_000_000)).duplicate);
}

test "frames without a trailer or tag pass through; a malformed trailer is not taken for one" {
    var fil = Filter.init(.{});
    var out: [512]u8 = undefined;
    var buf: [512]u8 = undefined;
    const plain = try gooseFrame(1, 1, false, &buf);
    const r = try fil.accept(plain, &out, 0);
    try testing.expectEqual(Kind.untagged, r.kind);
    try testing.expect(!r.duplicate);
    try testing.expect(r.frame.ptr == plain.ptr);
    try testing.expect(!(try fil.accept(plain, &out, 1)).duplicate);
    try testing.expectEqual(@as(u64, 2), fil.stats.untagged);

    // A suffix but a LAN id that is neither A nor B.
    var bad: [512]u8 = undefined;
    @memcpy(bad[0..plain.len], plain);
    var n = try appendRct(&bad, plain.len, 3, .a);
    bad[n - 4] = 0x30 | (bad[n - 4] & 0x0F);
    try testing.expect(parseRct(bad[0..n]) == null);
    // A size field larger than the payload.
    n = try appendRct(&bad, plain.len, 3, .a);
    std.mem.writeInt(u16, bad[n - 4 ..][0..2], (@as(u16, 0xA) << 12) | 0xFFF, .big);
    try testing.expect(parseRct(bad[0..n]) == null);
    // A size field below the trailer itself.
    std.mem.writeInt(u16, bad[n - 4 ..][0..2], (@as(u16, 0xA) << 12) | 5, .big);
    try testing.expect(parseRct(bad[0..n]) == null);
    // Forced modes ignore the other redundancy.
    var prp_only = Filter.init(.{ .mode = .prp });
    var tagged: [512]u8 = undefined;
    const t = try encodeHsr(plain, 0, 1, &tagged);
    try testing.expectEqual(Kind.untagged, (try prp_only.accept(t, &out, 0)).kind);
    var hsr_only = Filter.init(.{ .mode = .hsr });
    n = try appendRct(&bad, plain.len, 3, .a);
    try testing.expectEqual(Kind.untagged, (try hsr_only.accept(bad[0..n], &out, 0)).kind);
}

test "short frames and a too-small scratch buffer are errors, not panics" {
    var fil = Filter.init(.{});
    var out: [512]u8 = undefined;
    try testing.expectError(error.ShortFrame, fil.accept(&[_]u8{ 1, 2, 3 }, &out, 0));
    const dangling_vlan = @as([12]u8, @splat(0)) ++ [_]u8{ 0x81, 0x00, 0x00, 0x64 };
    try testing.expectError(error.ShortFrame, fil.accept(&dangling_vlan, &out, 0));
    var buf: [512]u8 = undefined;
    const plain = try gooseFrame(1, 1, false, &buf);
    var tagged: [512]u8 = undefined;
    const t = try encodeHsr(plain, 0, 1, &tagged);
    var small: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, fil.accept(t, &small, 0));
    try testing.expectError(error.BufferTooSmall, encodeHsr(plain, 0, 1, small[0..]));
    try testing.expectError(error.BufferTooSmall, appendRct(buf[0..plain.len], plain.len, 1, .a));
    // A tag cut off after the EtherType.
    try testing.expect(parseHsr(t[0..16]) == null);
}

test "the table is bounded: the least recently used source is evicted" {
    var fil = Filter.init(.{ .forget_ms = 0 });
    var out: [64]u8 = undefined;
    var buf: [512]u8 = undefined;
    const frame = struct {
        fn f(b: *[512]u8, src: u8, seq: u16) ![]const u8 {
            const plain = try gooseFrame(src, 1, false, b);
            const n = try appendRct(b, plain.len, seq, .a);
            return b[0..n];
        }
    }.f;
    var i: u16 = 0;
    while (i < max_sources) : (i += 1) {
        _ = try fil.accept(try frame(&buf, @intCast(i), 1), &out, i);
    }
    // One more source than there is room for: source 0, the oldest, goes.
    _ = try fil.accept(try frame(&buf, 200, 1), &out, 1000);
    try testing.expect(!(try fil.accept(try frame(&buf, 0, 1), &out, 1001)).duplicate);
    // A recent one survived.
    try testing.expect((try fil.accept(try frame(&buf, 200, 1), &out, 1002)).duplicate);
}
