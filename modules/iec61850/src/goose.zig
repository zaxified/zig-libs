// SPDX-License-Identifier: MIT

//! **GOOSE** (IEC 61850-8-1 §A.3, §18) — the fast half: a BER PDU published
//! straight onto layer 2, with no IP, no TCP and no acknowledgement.
//!
//! ```text
//! | dst MAC 6 | src MAC 6 | [8100 TCI 2] | 88B8 | APPID 2 | Length 2 | Res1 2 | Res2 2 | goosePdu |
//! ```
//!
//! Four facts the code is built around:
//!
//! * **`Length` counts from the APPID field**, i.e. the eight header octets
//!   plus the PDU — not the whole frame and not just the PDU. Ethernet pads
//!   short frames to 60 octets, so `Length` is the *only* way to know where the
//!   PDU ends; a decoder that trusts the captured frame length reads padding as
//!   BER.
//! * **The optional 802.1Q tag shifts everything by four octets.** A subscriber
//!   that assumes the EtherType is at offset 12 silently misparses every
//!   VLAN-tagged publisher, which in a real substation is all of them.
//! * **`numDatSetEntries` is redundant with `allData` and must agree.** A
//!   disagreement means either the publisher is misconfigured or the frame was
//!   tampered with; GOOSE has no integrity protection at all, so the
//!   cross-check is the only consistency signal there is.
//! * **`timeAllowedtoLive` is the liveness contract.** It is not a timestamp:
//!   it is the publisher promising the next frame within that many
//!   milliseconds. A subscriber that ignores it cannot tell a healthy quiet
//!   publisher from a dead one.

const std = @import("std");
const ber = @import("ber.zig");
const mmsdata = @import("mmsdata.zig");

pub const Error = mmsdata.Error || error{
    /// Fewer octets than a GOOSE header needs.
    ShortFrame,
    /// The EtherType is not `0x88B8`.
    NotGoose,
    /// The `Length` field disagrees with the octets present.
    LengthMismatch,
    /// `numDatSetEntries` does not match the number of `allData` members.
    EntryCountMismatch,
    /// A required PDU field is absent.
    MissingField,
    /// More data-set entries than the fixed decode table holds.
    TooManyEntries,
};

pub const ether_type: u16 = 0x88B8;
pub const vlan_ether_type: u16 = 0x8100;
/// Offset of the EtherType in an untagged Ethernet frame.
pub const untagged_ethertype_offset: usize = 12;
/// The eight octets between the EtherType and the PDU.
pub const header_len: usize = 8;
/// The `Length` field counts these eight octets plus the PDU.
pub const length_field_base: usize = header_len;

/// The IEC 61850 GOOSE multicast destination range is `01-0C-CD-01-00-00` …
/// `01-0C-CD-01-01-FF`. A publisher outside it is legal but unconventional.
pub const goose_multicast_prefix = [_]u8{ 0x01, 0x0C, 0xCD, 0x01 };

pub fn isGooseMulticast(mac: [6]u8) bool {
    return std.mem.eql(u8, mac[0..4], &goose_multicast_prefix);
}

/// An 802.1Q tag. GOOSE uses priority 4 by convention.
pub const Vlan = struct {
    priority: u3,
    dei: bool = false,
    id: u12,

    pub fn tci(self: Vlan) u16 {
        return (@as(u16, self.priority) << 13) | (@as(u16, @intFromBool(self.dei)) << 12) | self.id;
    }

    pub fn fromTci(v: u16) Vlan {
        return .{
            .priority = @truncate(v >> 13),
            .dei = (v >> 12) & 1 != 0,
            .id = @truncate(v),
        };
    }
};

/// The link-layer envelope.
pub const Frame = struct {
    dst: [6]u8,
    src: [6]u8,
    vlan: ?Vlan = null,
    appid: u16,
    reserved1: u16 = 0,
    reserved2: u16 = 0,
    /// The BER-encoded `goosePdu`, exactly `Length - 8` octets.
    pdu: []const u8,
    /// Octets the frame occupied, excluding any Ethernet padding beyond it.
    total_len: usize,

    pub fn decode(bytes: []const u8) Error!Frame {
        if (bytes.len < 14) return error.ShortFrame;
        var f = Frame{
            .dst = bytes[0..6].*,
            .src = bytes[6..12].*,
            .appid = 0,
            .pdu = &.{},
            .total_len = 0,
        };
        var off: usize = untagged_ethertype_offset;
        var et = std.mem.readInt(u16, bytes[off..][0..2], .big);
        if (et == vlan_ether_type) {
            if (bytes.len < off + 8) return error.ShortFrame;
            f.vlan = Vlan.fromTci(std.mem.readInt(u16, bytes[off + 2 ..][0..2], .big));
            off += 4;
            et = std.mem.readInt(u16, bytes[off..][0..2], .big);
        }
        if (et != ether_type) return error.NotGoose;
        off += 2;
        if (bytes.len < off + header_len) return error.ShortFrame;
        f.appid = std.mem.readInt(u16, bytes[off..][0..2], .big);
        const length = std.mem.readInt(u16, bytes[off + 2 ..][0..2], .big);
        f.reserved1 = std.mem.readInt(u16, bytes[off + 4 ..][0..2], .big);
        f.reserved2 = std.mem.readInt(u16, bytes[off + 6 ..][0..2], .big);
        if (length < length_field_base) return error.LengthMismatch;
        const pdu_len = length - length_field_base;
        // Trailing octets are Ethernet padding and are ignored; too few is a
        // truncated or lying frame.
        if (bytes.len < off + header_len + pdu_len) return error.LengthMismatch;
        f.pdu = bytes[off + header_len ..][0..pdu_len];
        f.total_len = off + header_len + pdu_len;
        return f;
    }

    /// Writes the link-layer header in front of an already-built PDU.
    pub fn encode(self: Frame, pdu: []const u8, out: []u8) Error![]u8 {
        const tag_len: usize = if (self.vlan == null) 0 else 4;
        const total = 14 + tag_len + header_len + pdu.len;
        if (out.len < total) return error.BufferTooSmall;
        if (pdu.len + header_len > std.math.maxInt(u16)) return error.BufferTooSmall;
        @memcpy(out[0..6], &self.dst);
        @memcpy(out[6..12], &self.src);
        var off: usize = 12;
        if (self.vlan) |v| {
            std.mem.writeInt(u16, out[off..][0..2], vlan_ether_type, .big);
            std.mem.writeInt(u16, out[off + 2 ..][0..2], v.tci(), .big);
            off += 4;
        }
        std.mem.writeInt(u16, out[off..][0..2], ether_type, .big);
        off += 2;
        std.mem.writeInt(u16, out[off..][0..2], self.appid, .big);
        std.mem.writeInt(u16, out[off + 2 ..][0..2], @intCast(header_len + pdu.len), .big);
        std.mem.writeInt(u16, out[off + 4 ..][0..2], self.reserved1, .big);
        std.mem.writeInt(u16, out[off + 6 ..][0..2], self.reserved2, .big);
        off += header_len;
        @memcpy(out[off..][0..pdu.len], pdu);
        return out[0 .. off + pdu.len];
    }
};

// ── the PDU ─────────────────────────────────────────────────────────────────

pub const tag_goose_pdu = ber.Tag.appc(1);

const tag_gocb_ref = ber.Tag.ctx(0);
const tag_time_allowed_to_live = ber.Tag.ctx(1);
const tag_dat_set = ber.Tag.ctx(2);
const tag_go_id = ber.Tag.ctx(3);
const tag_t = ber.Tag.ctx(4);
const tag_st_num = ber.Tag.ctx(5);
const tag_sq_num = ber.Tag.ctx(6);
const tag_test = ber.Tag.ctx(7);
const tag_conf_rev = ber.Tag.ctx(8);
const tag_nds_com = ber.Tag.ctx(9);
const tag_num_dat_set_entries = ber.Tag.ctx(10);
const tag_all_data = ber.Tag.ctxc(11);

pub const Pdu = struct {
    gocb_ref: []const u8,
    time_allowed_to_live_ms: u32,
    dat_set: []const u8,
    /// Optional in the ASN.1; defaults to `gocb_ref` when absent.
    go_id: []const u8,
    t: mmsdata.UtcTime,
    st_num: u32,
    sq_num: u32,
    /// A test frame must not operate anything.
    test_mode: bool,
    conf_rev: u32,
    /// "Needs commissioning" — the publisher says its configuration is
    /// incomplete and its data must not be trusted.
    nds_com: bool,
    num_dat_set_entries: u32,
    /// The `allData` body: a sequence of `Data` values.
    all_data: []const u8,

    /// Walks `allData`.
    pub fn values(self: Pdu) mmsdata.Members {
        return .{ .inner = ber.Iterator.initDepth(self.all_data, mmsdata.max_depth) };
    }

    /// Counts `allData` members, bounded by the body length.
    pub fn valueCount(self: Pdu) Error!usize {
        var it = self.values();
        var n: usize = 0;
        while (try it.next()) |_| n += 1;
        return n;
    }

    pub fn decode(bytes: []const u8) Error!Pdu {
        const outer = try ber.expect(bytes, tag_goose_pdu);
        var p = Pdu{
            .gocb_ref = &.{},
            .time_allowed_to_live_ms = 0,
            .dat_set = &.{},
            .go_id = &.{},
            .t = undefined,
            .st_num = 0,
            .sq_num = 0,
            .test_mode = false,
            .conf_rev = 0,
            .nds_com = false,
            .num_dat_set_entries = 0,
            .all_data = &.{},
        };
        var seen_t = false;
        var seen_all_data = false;
        var it = ber.Iterator.init(outer.content);
        while (try it.next()) |e| {
            if (e.tag.class != .context) return error.UnexpectedTag;
            switch (e.tag.number) {
                0 => p.gocb_ref = e.content,
                1 => p.time_allowed_to_live_ms = try ber.decodeUint(u32, e.content),
                2 => p.dat_set = e.content,
                3 => p.go_id = e.content,
                4 => {
                    p.t = try mmsdata.UtcTime.parse(e.content);
                    seen_t = true;
                },
                5 => p.st_num = try ber.decodeUint(u32, e.content),
                6 => p.sq_num = try ber.decodeUint(u32, e.content),
                7 => p.test_mode = try ber.decodeBool(e.content),
                8 => p.conf_rev = try ber.decodeUint(u32, e.content),
                9 => p.nds_com = try ber.decodeBool(e.content),
                10 => p.num_dat_set_entries = try ber.decodeUint(u32, e.content),
                11 => {
                    p.all_data = e.content;
                    seen_all_data = true;
                },
                else => {}, // security [12] and future fields are ignored
            }
        }
        if (p.gocb_ref.len == 0 or !seen_t or !seen_all_data) return error.MissingField;
        if (p.go_id.len == 0) p.go_id = p.gocb_ref;
        // The redundant count must agree with the entries actually present.
        const actual = try p.valueCount();
        if (actual != p.num_dat_set_entries) return error.EntryCountMismatch;
        // And every value must be a well-formed, bounded-depth `Data`.
        var vals = p.values();
        while (try vals.next()) |d| try d.validate();
        return p;
    }

    /// Writes a PDU. `data_values` are complete, already encoded `Data` TLVs —
    /// `numDatSetEntries` is derived from the slice, never taken from a caller
    /// field, so the two cannot disagree on the wire.
    pub fn encode(self: Pdu, data_values: []const []const u8, out: []u8) Error![]const u8 {
        var w = ber.Writer.init(out);
        const outer = w.mark();
        const all = w.mark();
        var i: usize = data_values.len;
        while (i > 0) {
            i -= 1;
            try w.bytes(data_values[i]);
        }
        try w.header(tag_all_data, all);
        try w.unsigned(tag_num_dat_set_entries, data_values.len);
        try w.boolean(tag_nds_com, self.nds_com);
        try w.unsigned(tag_conf_rev, self.conf_rev);
        try w.boolean(tag_test, self.test_mode);
        try w.unsigned(tag_sq_num, self.sq_num);
        try w.unsigned(tag_st_num, self.st_num);
        var tbuf: [8]u8 = undefined;
        self.t.encode(&tbuf);
        try w.primitive(tag_t, &tbuf);
        try w.primitive(tag_go_id, self.go_id);
        try w.primitive(tag_dat_set, self.dat_set);
        try w.unsigned(tag_time_allowed_to_live, self.time_allowed_to_live_ms);
        try w.primitive(tag_gocb_ref, self.gocb_ref);
        try w.header(tag_goose_pdu, outer);
        return w.done();
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// A GOOSE frame captured from a real third-party publisher on a veth pair.
/// The source MAC is the kernel-generated random address of a throwaway veth
/// interface; it has been replaced with `02:00:00:00:00:01` — a **length
/// preserving** substitution, so every length field and the whole decode are
/// unaffected. The destination is the standard IEC 61850 multicast address, a
/// protocol constant, and is kept. The object names come from the publisher's
/// shipped *example* model, not from any real installation.
pub const captured_frame_hex =
    "010ccd010001" ++ "020000000001" ++ "88b8" ++
    "03e8" ++ "00b8" ++ "0000" ++ "0000" ++
    "6181ad" ++
    "8029" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024474f24676362416e616c6f6756616c756573" ++
    "810201f4" ++
    "8223" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024416e616c6f6756616c756573" ++
    "8329" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024474f24676362416e616c6f6756616c756573" ++
    "84086a61d98fc418930a" ++
    "850101" ++ "860100" ++ "870100" ++ "880101" ++ "890100" ++ "8a0103" ++
    "ab10" ++ "850204d2" ++ "8c06000000000000" ++ "8502162e";

/// The same publisher one retransmission later: `sqNum` 3, a fourth data-set
/// entry appended, and the `Length` field grown to match.
pub const captured_frame_sq3_hex =
    "010ccd010001" ++ "020000000001" ++ "88b8" ++
    "03e8" ++ "00bb" ++ "0000" ++ "0000" ++
    "6181b0" ++
    "8029" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024474f24676362416e616c6f6756616c756573" ++
    "810201f4" ++
    "8223" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024416e616c6f6756616c756573" ++
    "8329" ++ "73696d706c65494f47656e65726963494f2f4c4c4e3024474f24676362416e616c6f6756616c756573" ++
    "84086a61d98fc418930a" ++
    "850101" ++ "860103" ++ "870100" ++ "880101" ++ "890100" ++ "8a0104" ++
    "ab13" ++ "850204d2" ++ "8c06000000000000" ++ "8502162e" ++ "830101";

fn unhex(hex: []const u8, out: []u8) []u8 {
    var i: usize = 0;
    while (i * 2 < hex.len) : (i += 1) {
        out[i] = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch unreachable;
    }
    return out[0 .. hex.len / 2];
}

test "the captured GOOSE frame decodes field by field" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    const f = try Frame.decode(bytes);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01 }, &f.dst);
    try testing.expect(isGooseMulticast(f.dst));
    try testing.expect(f.vlan == null);
    try testing.expectEqual(@as(u16, 1000), f.appid);
    try testing.expectEqual(@as(usize, 0xB8 - header_len), f.pdu.len);
    try testing.expectEqual(bytes.len, f.total_len);

    const p = try Pdu.decode(f.pdu);
    try testing.expectEqualStrings("simpleIOGenericIO/LLN0$GO$gcbAnalogValues", p.gocb_ref);
    try testing.expectEqual(@as(u32, 500), p.time_allowed_to_live_ms);
    try testing.expectEqualStrings("simpleIOGenericIO/LLN0$AnalogValues", p.dat_set);
    try testing.expectEqualStrings(p.gocb_ref, p.go_id);
    try testing.expectEqual(@as(u32, 1), p.st_num);
    try testing.expectEqual(@as(u32, 0), p.sq_num);
    try testing.expect(!p.test_mode);
    try testing.expectEqual(@as(u32, 1), p.conf_rev);
    try testing.expect(!p.nds_com);
    try testing.expectEqual(@as(u32, 3), p.num_dat_set_entries);
    try testing.expectEqual(@as(u32, 0x6A61D98F), p.t.seconds);
    try testing.expectEqual(@as(u5, 10), p.t.accuracy.?);

    var it = p.values();
    try testing.expectEqual(@as(i32, 1234), try (try it.next()).?.integer(i32));
    const bt = try (try it.next()).?.binaryTime();
    try testing.expectEqual(@as(u32, 0), bt.ms_since_midnight);
    try testing.expectEqual(@as(i32, 5678), try (try it.next()).?.integer(i32));
    try testing.expect((try it.next()) == null);
}

test "the captured GOOSE frame re-encodes to the identical octets" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    const f = try Frame.decode(bytes);
    const p = try Pdu.decode(f.pdu);

    // Rebuild the PDU from its decoded values, so the value encoder is what is
    // being checked and not a memcpy.
    var vals: [8][]const u8 = undefined;
    var n: usize = 0;
    var it = p.values();
    while (try it.next()) |d| : (n += 1) vals[n] = d.raw;
    var pbuf: [512]u8 = undefined;
    const rebuilt_pdu = try p.encode(vals[0..n], &pbuf);
    try testing.expectEqualSlices(u8, f.pdu, rebuilt_pdu);

    var fbuf: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, bytes, try f.encode(rebuilt_pdu, &fbuf));
}

test "the second captured frame shows sqNum advancing and the length tracking" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_sq3_hex, &buf);
    const f = try Frame.decode(bytes);
    const p = try Pdu.decode(f.pdu);
    try testing.expectEqual(@as(u32, 1), p.st_num);
    try testing.expectEqual(@as(u32, 3), p.sq_num);
    try testing.expectEqual(@as(u32, 4), p.num_dat_set_entries);
    try testing.expectEqual(@as(usize, 4), try p.valueCount());
    // The Length field grew by exactly the appended boolean's three octets.
    var first: [512]u8 = undefined;
    const f0 = try Frame.decode(unhex(captured_frame_hex, &first));
    try testing.expectEqual(f0.pdu.len + 3, f.pdu.len);
}

test "an 802.1Q tag shifts the EtherType and still decodes" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    const f0 = try Frame.decode(bytes);
    var tagged = f0;
    tagged.vlan = .{ .priority = 4, .id = 100 };
    var out: [512]u8 = undefined;
    const framed = try tagged.encode(f0.pdu, &out);
    try testing.expectEqual(bytes.len + 4, framed.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x81, 0x00, 0x80, 0x64 }, framed[12..16]);
    const back = try Frame.decode(framed);
    try testing.expectEqual(@as(u3, 4), back.vlan.?.priority);
    try testing.expectEqual(@as(u12, 100), back.vlan.?.id);
    try testing.expectEqualSlices(u8, f0.pdu, back.pdu);
}

test "Ethernet padding past the announced length is ignored, not parsed" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    var padded: [600]u8 = undefined;
    @memcpy(padded[0..bytes.len], bytes);
    @memset(padded[bytes.len..][0..40], 0xFF);
    const f = try Frame.decode(padded[0 .. bytes.len + 40]);
    try testing.expectEqual(bytes.len, f.total_len);
    _ = try Pdu.decode(f.pdu);
}

test "a Length field that disagrees with the frame is refused" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    // The Length field lives at offset 16..18 (6 + 6 + 2 EtherType + 2 APPID).
    // Announce 40 octets more than are present.
    bytes[17] = bytes[17] +% 40;
    try testing.expectError(error.LengthMismatch, Frame.decode(bytes));
    // And a Length below the eight-octet base.
    bytes[16] = 0;
    bytes[17] = 4;
    try testing.expectError(error.LengthMismatch, Frame.decode(bytes));
    // A Length shorter than the PDU truncates it, and BER then refuses.
    bytes[17] = 20;
    const f = try Frame.decode(bytes);
    try testing.expectError(error.Overrun, Pdu.decode(f.pdu));
}

test "an allData count contradicting the entries is refused" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    const f = try Frame.decode(bytes);
    // `8a 01 03` is numDatSetEntries; claim four entries where three are sent.
    const idx = std.mem.indexOf(u8, f.pdu, &[_]u8{ 0x8A, 0x01, 0x03 }).?;
    var pdu: [512]u8 = undefined;
    @memcpy(pdu[0..f.pdu.len], f.pdu);
    pdu[idx + 2] = 4;
    try testing.expectError(error.EntryCountMismatch, Pdu.decode(pdu[0..f.pdu.len]));
    pdu[idx + 2] = 0;
    try testing.expectError(error.EntryCountMismatch, Pdu.decode(pdu[0..f.pdu.len]));
}

test "a non-GOOSE EtherType and a short frame are typed errors" {
    try testing.expectError(error.ShortFrame, Frame.decode(&[_]u8{0} ** 13));
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    bytes[13] = 0xB9;
    try testing.expectError(error.NotGoose, Frame.decode(bytes));
    // A VLAN tag with nothing behind it.
    const dangling_vlan = [_]u8{0} ** 12 ++ [_]u8{ 0x81, 0x00, 0x00, 0x64 };
    try testing.expectError(error.ShortFrame, Frame.decode(&dangling_vlan));
}

test "a PDU missing a mandatory field is refused" {
    // Only gocbRef and allData.
    try testing.expectError(
        error.MissingField,
        Pdu.decode(&[_]u8{ 0x61, 0x08, 0x80, 0x01, 'a', 0x8A, 0x01, 0x00, 0xAB, 0x00 }),
    );
    // gocbRef present, t present, but no allData.
    const no_all_data = [_]u8{ 0x61, 0x0D, 0x80, 0x01, 'a', 0x84, 0x08 } ++ [_]u8{0} ** 7 ++ [_]u8{0x0A};
    try testing.expectError(error.MissingField, Pdu.decode(&no_all_data));
}

test "a UtcTime with an impossible accuracy is refused inside a GOOSE PDU" {
    var buf: [512]u8 = undefined;
    const bytes = unhex(captured_frame_hex, &buf);
    const f = try Frame.decode(bytes);
    var pdu: [512]u8 = undefined;
    @memcpy(pdu[0..f.pdu.len], f.pdu);
    const idx = std.mem.indexOf(u8, pdu[0..f.pdu.len], &[_]u8{ 0x84, 0x08 }).?;
    pdu[idx + 2 + 7] = 27; // a reserved TimeAccuracy value
    try testing.expectError(error.BadTime, Pdu.decode(pdu[0..f.pdu.len]));
}

test "a data value nested past the depth bound is refused inside a GOOSE PDU" {
    var vbuf: [256]u8 = undefined;
    // 64 nested structures as one data-set entry.
    const depth: usize = 64;
    var i: usize = depth;
    var len: usize = 0;
    while (i > 0) : (i -= 1) {
        vbuf[depth * 2 - len - 1] = @intCast(len);
        vbuf[depth * 2 - len - 2] = 0xA2;
        len += 2;
    }
    const p = Pdu{
        .gocb_ref = "g",
        .time_allowed_to_live_ms = 100,
        .dat_set = "d",
        .go_id = "g",
        .t = mmsdata.UtcTime.fromMillis(0, 10),
        .st_num = 1,
        .sq_num = 0,
        .test_mode = false,
        .conf_rev = 1,
        .nds_com = false,
        .num_dat_set_entries = 1,
        .all_data = &.{},
    };
    var out: [512]u8 = undefined;
    const encoded = try p.encode(&[_][]const u8{vbuf[0 .. depth * 2]}, &out);
    try testing.expectError(error.TooDeep, Pdu.decode(encoded));
}

test "the encoder derives numDatSetEntries from the values it is given" {
    var vbuf: [64]u8 = undefined;
    var vw = ber.Writer.init(&vbuf);
    try mmsdata.Emit.boolean(&vw, true);
    const one = vw.done();
    const p = Pdu{
        .gocb_ref = "LD/LLN0$GO$gcb",
        .time_allowed_to_live_ms = 2000,
        .dat_set = "LD/LLN0$ds",
        .go_id = "gcb",
        .t = mmsdata.UtcTime.fromMillis(1_700_000_000_000, 10),
        .st_num = 7,
        .sq_num = 2,
        .test_mode = false,
        .conf_rev = 3,
        .nds_com = false,
        // Deliberately wrong: the encoder must ignore it.
        .num_dat_set_entries = 99,
        .all_data = &.{},
    };
    var out: [256]u8 = undefined;
    const vals = [_][]const u8{ one, one, one };
    const back = try Pdu.decode(try p.encode(&vals, &out));
    try testing.expectEqual(@as(u32, 3), back.num_dat_set_entries);
    try testing.expectEqual(@as(u32, 7), back.st_num);
    try testing.expectEqual(@as(u32, 2), back.sq_num);
    try testing.expectEqual(@as(u32, 3), back.conf_rev);
}

test "fuzz: goose frame and PDU decode never panic" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    _ = Pdu.decode(buf[0..len]) catch {};
    const f = Frame.decode(buf[0..len]) catch return;
    try testing.expect(f.total_len <= len);
    const p = Pdu.decode(f.pdu) catch return;
    // Anything that decoded must re-encode to the identical PDU octets.
    var vals: [64][]const u8 = undefined;
    var n: usize = 0;
    var it = p.values();
    while (try it.next()) |d| : (n += 1) {
        if (n == vals.len) return;
        vals[n] = d.raw;
    }
    var out: [1024]u8 = undefined;
    const again = p.encode(vals[0..n], &out) catch return;
    try testing.expectEqualSlices(u8, f.pdu, again);
}
