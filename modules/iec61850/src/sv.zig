// SPDX-License-Identifier: MIT

//! **Sampled Values** (IEC 61850-9-2) — the same link-layer envelope as GOOSE
//! with EtherType `0x88BA`, and a BER PDU that carries several ASDUs per frame.
//!
//! This came almost free once the GOOSE frame and the BER codec existed, which
//! is why it is here rather than deferred: `savPdu` is a `noASDU` count and a
//! `SEQUENCE OF ASDU`, and each ASDU is a handful of fixed-width octet strings.
//!
//! Two differences from GOOSE are worth stating:
//!
//! * **`seqData` is opaque here.** The 9-2LE profile fixes it at eight
//!   `{value, quality}` pairs of four octets each (four currents, four
//!   voltages), but that layout is a *profile*, not the standard, and other
//!   profiles differ. `Asdu.dataset9_2le` decodes the LE layout explicitly and
//!   is the only place the profile is assumed.
//! * **`noASDU` must agree with `seqASDU`**, the same redundant-count check
//!   GOOSE needs, and for the same reason: there is no integrity protection.
//!
//! What is **not** here: publisher/subscriber timing. SV runs at 4000 or 4800
//! frames a second with a hard jitter budget; a state machine for that belongs
//! with a real-time scheduler, not in a codec. This module decodes and encodes
//! frames. See SPEC.md's deferred list.

const std = @import("std");
const ber = @import("ber.zig");
const goose = @import("goose.zig");
const mmsdata = @import("mmsdata.zig");

pub const Error = goose.Error;

pub const ether_type: u16 = 0x88BA;

/// The IEC 61850-9-2 multicast destination range is `01-0C-CD-04-00-00` …
pub const sv_multicast_prefix = [_]u8{ 0x01, 0x0C, 0xCD, 0x04 };

pub fn isSvMulticast(mac: [6]u8) bool {
    return std.mem.eql(u8, mac[0..4], &sv_multicast_prefix);
}

pub const tag_sav_pdu = ber.Tag.appc(0);

const tag_no_asdu = ber.Tag.ctx(0);
const tag_security = ber.Tag.ctx(1);
const tag_seq_asdu = ber.Tag.ctxc(2);

const tag_sv_id = ber.Tag.ctx(0);
const tag_dat_set = ber.Tag.ctx(1);
const tag_smp_cnt = ber.Tag.ctx(2);
const tag_conf_rev = ber.Tag.ctx(3);
const tag_refr_tm = ber.Tag.ctx(4);
const tag_smp_synch = ber.Tag.ctx(5);
const tag_smp_rate = ber.Tag.ctx(6);
const tag_seq_data = ber.Tag.ctx(7);
const tag_smp_mod = ber.Tag.ctx(8);

/// Clock synchronisation state of the merging unit. Anything other than
/// `global` means the samples cannot be correlated across devices.
pub const SmpSynch = enum(u8) {
    none = 0,
    local = 1,
    global = 2,
    _,
};

pub const Asdu = struct {
    sv_id: []const u8,
    dat_set: ?[]const u8 = null,
    smp_cnt: u16,
    conf_rev: u32,
    refr_tm: ?mmsdata.UtcTime = null,
    smp_synch: SmpSynch = .none,
    smp_rate: ?u16 = null,
    /// Raw sample payload; the layout is profile-specific.
    seq_data: []const u8,
    smp_mod: ?u16 = null,

    /// The 9-2LE payload: eight `{i32 value, u32 quality}` pairs — four
    /// currents then four voltages.
    pub const Le = struct {
        value: [8]i32,
        quality: [8]u32,
    };

    /// Decodes `seqData` as the 9-2 "Light Edition" dataset. Refuses anything
    /// that is not exactly 64 octets rather than reading a shorter profile's
    /// payload out of bounds.
    pub fn dataset9_2le(self: Asdu) Error!Le {
        if (self.seq_data.len != 64) return error.LengthMismatch;
        var le: Le = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            le.value[i] = std.mem.readInt(i32, self.seq_data[i * 8 ..][0..4], .big);
            le.quality[i] = std.mem.readInt(u32, self.seq_data[i * 8 + 4 ..][0..4], .big);
        }
        return le;
    }

    pub fn decode(bytes: []const u8) Error!Asdu {
        const e = try ber.expect(bytes, ber.Tag.sequence);
        var a = Asdu{ .sv_id = &.{}, .smp_cnt = 0, .conf_rev = 0, .seq_data = &.{} };
        var seen_id = false;
        var seen_data = false;
        var it = ber.Iterator.init(e.content);
        while (try it.next()) |f| {
            if (f.tag.class != .context) return error.UnexpectedTag;
            switch (f.tag.number) {
                0 => {
                    a.sv_id = f.content;
                    seen_id = true;
                },
                1 => a.dat_set = f.content,
                2 => {
                    if (f.content.len != 2) return error.LengthMismatch;
                    a.smp_cnt = std.mem.readInt(u16, f.content[0..2], .big);
                },
                3 => {
                    if (f.content.len != 4) return error.LengthMismatch;
                    a.conf_rev = std.mem.readInt(u32, f.content[0..4], .big);
                },
                4 => a.refr_tm = try mmsdata.UtcTime.parse(f.content),
                5 => {
                    if (f.content.len != 1) return error.LengthMismatch;
                    a.smp_synch = @enumFromInt(f.content[0]);
                },
                6 => {
                    if (f.content.len != 2) return error.LengthMismatch;
                    a.smp_rate = std.mem.readInt(u16, f.content[0..2], .big);
                },
                7 => {
                    a.seq_data = f.content;
                    seen_data = true;
                },
                8 => {
                    if (f.content.len != 2) return error.LengthMismatch;
                    a.smp_mod = std.mem.readInt(u16, f.content[0..2], .big);
                },
                else => {},
            }
        }
        if (!seen_id or !seen_data) return error.MissingField;
        return a;
    }

    pub fn emit(self: Asdu, w: *ber.Writer) Error!void {
        const m = w.mark();
        if (self.smp_mod) |v| try emitU16(w, tag_smp_mod, v);
        try w.primitive(tag_seq_data, self.seq_data);
        if (self.smp_rate) |v| try emitU16(w, tag_smp_rate, v);
        try w.primitive(tag_smp_synch, &[_]u8{@intFromEnum(self.smp_synch)});
        if (self.refr_tm) |t| {
            var tmp: [8]u8 = undefined;
            t.encode(&tmp);
            try w.primitive(tag_refr_tm, &tmp);
        }
        var cr: [4]u8 = undefined;
        std.mem.writeInt(u32, &cr, self.conf_rev, .big);
        try w.primitive(tag_conf_rev, &cr);
        try emitU16(w, tag_smp_cnt, self.smp_cnt);
        if (self.dat_set) |d| try w.primitive(tag_dat_set, d);
        try w.primitive(tag_sv_id, self.sv_id);
        try w.header(ber.Tag.sequence, m);
    }

    fn emitU16(w: *ber.Writer, tag: ber.Tag, v: u16) Error!void {
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, v, .big);
        try w.primitive(tag, &tmp);
    }
};

pub const max_asdus: usize = 8;

pub const SavPdu = struct {
    no_asdu: u8,
    asdus: [max_asdus]Asdu = undefined,
    count: u8 = 0,

    pub fn list(self: *const SavPdu) []const Asdu {
        return self.asdus[0..self.count];
    }

    pub fn decode(bytes: []const u8) Error!SavPdu {
        const outer = try ber.expect(bytes, tag_sav_pdu);
        var p = SavPdu{ .no_asdu = 0 };
        var seen_count = false;
        var it = ber.Iterator.init(outer.content);
        while (try it.next()) |e| {
            if (e.tag.eql(tag_no_asdu)) {
                p.no_asdu = try ber.decodeUint(u8, e.content);
                seen_count = true;
            } else if (e.tag.eql(tag_seq_asdu)) {
                var inner = ber.Iterator.init(e.content);
                while (try inner.next()) |a| {
                    if (p.count == max_asdus) return error.TooManyEntries;
                    p.asdus[p.count] = try Asdu.decode(a.raw);
                    p.count += 1;
                }
            }
        }
        if (!seen_count) return error.MissingField;
        // The redundant count must agree, exactly as in GOOSE.
        if (p.no_asdu != p.count) return error.EntryCountMismatch;
        return p;
    }

    /// Encodes; `noASDU` is derived from the ASDUs given, never from the field.
    pub fn encode(asdus: []const Asdu, out: []u8) Error![]const u8 {
        var w = ber.Writer.init(out);
        const outer = w.mark();
        const seq = w.mark();
        var i: usize = asdus.len;
        while (i > 0) {
            i -= 1;
            try asdus[i].emit(&w);
        }
        try w.header(tag_seq_asdu, seq);
        try w.unsigned(tag_no_asdu, asdus.len);
        try w.header(tag_sav_pdu, outer);
        return w.done();
    }
};

/// The link-layer envelope, identical to GOOSE apart from the EtherType.
pub fn decodeFrame(bytes: []const u8) Error!goose.Frame {
    if (bytes.len < 14) return error.ShortFrame;
    var off: usize = goose.untagged_ethertype_offset;
    var vlan: ?goose.Vlan = null;
    var et = std.mem.readInt(u16, bytes[off..][0..2], .big);
    if (et == goose.vlan_ether_type) {
        if (bytes.len < off + 8) return error.ShortFrame;
        vlan = goose.Vlan.fromTci(std.mem.readInt(u16, bytes[off + 2 ..][0..2], .big));
        off += 4;
        et = std.mem.readInt(u16, bytes[off..][0..2], .big);
    }
    if (et != ether_type) return error.NotGoose;
    off += 2;
    if (bytes.len < off + goose.header_len) return error.ShortFrame;
    const appid = std.mem.readInt(u16, bytes[off..][0..2], .big);
    const length = std.mem.readInt(u16, bytes[off + 2 ..][0..2], .big);
    if (length < goose.header_len) return error.LengthMismatch;
    const pdu_len = length - goose.header_len;
    if (bytes.len < off + goose.header_len + pdu_len) return error.LengthMismatch;
    return .{
        .dst = bytes[0..6].*,
        .src = bytes[6..12].*,
        .vlan = vlan,
        .appid = appid,
        .reserved1 = std.mem.readInt(u16, bytes[off + 4 ..][0..2], .big),
        .reserved2 = std.mem.readInt(u16, bytes[off + 6 ..][0..2], .big),
        .pdu = bytes[off + goose.header_len ..][0..pdu_len],
        .total_len = off + goose.header_len + pdu_len,
    };
}

/// Writes the SV link-layer header in front of a `savPdu`.
pub fn encodeFrame(f: goose.Frame, pdu: []const u8, out: []u8) Error![]u8 {
    const tag_len: usize = if (f.vlan == null) 0 else 4;
    const total = 14 + tag_len + goose.header_len + pdu.len;
    if (out.len < total) return error.BufferTooSmall;
    @memcpy(out[0..6], &f.dst);
    @memcpy(out[6..12], &f.src);
    var off: usize = 12;
    if (f.vlan) |v| {
        std.mem.writeInt(u16, out[off..][0..2], goose.vlan_ether_type, .big);
        std.mem.writeInt(u16, out[off + 2 ..][0..2], v.tci(), .big);
        off += 4;
    }
    std.mem.writeInt(u16, out[off..][0..2], ether_type, .big);
    off += 2;
    std.mem.writeInt(u16, out[off..][0..2], f.appid, .big);
    std.mem.writeInt(u16, out[off + 2 ..][0..2], @intCast(goose.header_len + pdu.len), .big);
    std.mem.writeInt(u16, out[off + 4 ..][0..2], f.reserved1, .big);
    std.mem.writeInt(u16, out[off + 6 ..][0..2], f.reserved2, .big);
    off += goose.header_len;
    @memcpy(out[off..][0..pdu.len], pdu);
    return out[0 .. off + pdu.len];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// An SV frame captured from a real third-party publisher on a veth pair. The
/// source MAC (a kernel-generated random veth address) is replaced with
/// `02:00:00:00:00:01`, a **length-preserving** substitution; the destination
/// is the standard multicast address and is kept. `svpub1`/`svpub2` are the
/// publisher's shipped example stream ids.
pub const captured_frame_hex =
    "010ccd010001" ++ "020000000001" ++ "88ba" ++
    "4000" ++ "0061" ++ "0000" ++ "0000" ++
    "6057" ++
    "800102" ++
    "a252" ++
    "3027" ++ "8006" ++ "737670756231" ++ "82020001" ++ "830400000001" ++ "850100" ++
    "8710" ++ "449a522b3dfcd35b6a61d996e147ae00" ++
    "3027" ++ "8006" ++ "737670756232" ++ "82020001" ++ "830400000001" ++ "850100" ++
    "8710" ++ "451a522b3e7cd35b6a61d996e147ae00";

fn unhex(hex: []const u8, out: []u8) []u8 {
    var i: usize = 0;
    while (i * 2 < hex.len) : (i += 1) {
        out[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch unreachable;
    }
    return out[0 .. hex.len / 2];
}

test "the captured SV frame decodes field by field" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    const f = try decodeFrame(bytes);
    try testing.expectEqual(@as(u16, 0x4000), f.appid);
    try testing.expectEqual(bytes.len, f.total_len);

    const p = try SavPdu.decode(f.pdu);
    try testing.expectEqual(@as(u8, 2), p.no_asdu);
    try testing.expectEqual(@as(u8, 2), p.count);

    const a = p.list()[0];
    try testing.expectEqualStrings("svpub1", a.sv_id);
    try testing.expectEqual(@as(u16, 1), a.smp_cnt);
    try testing.expectEqual(@as(u32, 1), a.conf_rev);
    try testing.expectEqual(SmpSynch.none, a.smp_synch);
    try testing.expectEqual(@as(usize, 16), a.seq_data.len);
    try testing.expect(a.refr_tm == null);
    try testing.expectEqualStrings("svpub2", p.list()[1].sv_id);
}

test "the captured SV frame re-encodes to the identical octets" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    const f = try decodeFrame(bytes);
    const p = try SavPdu.decode(f.pdu);
    var pbuf: [512]u8 = undefined;
    const pdu = try SavPdu.encode(p.list(), &pbuf);
    try testing.expectEqualSlices(u8, f.pdu, pdu);
    var fbuf: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, bytes, try encodeFrame(f, pdu, &fbuf));
}

test "noASDU disagreeing with seqASDU is refused" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    const f = try decodeFrame(bytes);
    var pdu: [512]u8 = undefined;
    @memcpy(pdu[0..f.pdu.len], f.pdu);
    const idx = std.mem.indexOf(u8, pdu[0..f.pdu.len], &[_]u8{ 0x80, 0x01, 0x02 }).?;
    pdu[idx + 2] = 3;
    try testing.expectError(error.EntryCountMismatch, SavPdu.decode(pdu[0..f.pdu.len]));
}

test "a 9-2LE dataset decodes into value/quality pairs" {
    var payload: [64]u8 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        std.mem.writeInt(i32, payload[i * 8 ..][0..4], @as(i32, @intCast(i)) * -1000, .big);
        std.mem.writeInt(u32, payload[i * 8 + 4 ..][0..4], @intCast(i), .big);
    }
    const a = Asdu{
        .sv_id = "MU01",
        .smp_cnt = 4000,
        .conf_rev = 1,
        .smp_synch = .global,
        .smp_rate = 4000,
        .seq_data = &payload,
    };
    var out: [512]u8 = undefined;
    const p = try SavPdu.decode(try SavPdu.encode(&[_]Asdu{a}, &out));
    const back = p.list()[0];
    try testing.expectEqual(SmpSynch.global, back.smp_synch);
    try testing.expectEqual(@as(u16, 4000), back.smp_rate.?);
    const le = try back.dataset9_2le();
    try testing.expectEqual(@as(i32, 0), le.value[0]);
    try testing.expectEqual(@as(i32, -7000), le.value[7]);
    try testing.expectEqual(@as(u32, 7), le.quality[7]);

    // The captured publisher's 16-octet payload is not the LE profile.
    var buf: [512]u8 = undefined;
    const f = try decodeFrame(unhex(captured_frame_hex, &buf));
    const cap = try SavPdu.decode(f.pdu);
    try testing.expectError(error.LengthMismatch, cap.list()[0].dataset9_2le());
}

test "fixed-width fields of the wrong width are refused" {
    // smpCnt with three octets.
    try testing.expectError(
        error.LengthMismatch,
        Asdu.decode(&[_]u8{ 0x30, 0x0A, 0x80, 0x01, 'a', 0x82, 0x03, 0, 0, 1, 0x87, 0x00 }),
    );
    // confRev with two.
    try testing.expectError(
        error.LengthMismatch,
        Asdu.decode(&[_]u8{ 0x30, 0x09, 0x80, 0x01, 'a', 0x83, 0x02, 0, 1, 0x87, 0x00 }),
    );
    // An ASDU with no svID.
    try testing.expectError(error.MissingField, Asdu.decode(&[_]u8{ 0x30, 0x02, 0x87, 0x00 }));
}

test "an SV frame with a GOOSE EtherType is refused" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    bytes[13] = 0xB8;
    try testing.expectError(error.NotGoose, decodeFrame(bytes));
    try testing.expectError(error.ShortFrame, decodeFrame(&[_]u8{0} ** 10));
}

test "an SV frame carries a VLAN tag the same way GOOSE does" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    var f = try decodeFrame(bytes);
    const pdu_copy = f.pdu;
    f.vlan = .{ .priority = 4, .id = 5 };
    var out: [512]u8 = undefined;
    const framed = try encodeFrame(f, pdu_copy, &out);
    const back = try decodeFrame(framed);
    try testing.expectEqual(@as(u12, 5), back.vlan.?.id);
    try testing.expectEqualSlices(u8, pdu_copy, back.pdu);
}

test "fuzz: sv decode never panics" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = Asdu.decode(buf[0..len]) catch {};
    _ = SavPdu.decode(buf[0..len]) catch {};
    const f = decodeFrame(buf[0..len]) catch return;
    const p = SavPdu.decode(f.pdu) catch return;
    var out: [1024]u8 = undefined;
    const again = SavPdu.encode(p.list(), &out) catch return;
    try testing.expectEqualSlices(u8, f.pdu, again);
}
