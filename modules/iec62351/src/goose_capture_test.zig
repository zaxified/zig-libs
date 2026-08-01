// SPDX-License-Identifier: MIT

//! Real IEC 61850-8-1 GOOSE frames, vendored from a third-party capture, run
//! through this module's own frame/extension decoder. See `../NOTICE` for the
//! exact source, the frames excluded and why, and its licence.
//!
//! ## What a real GOOSE capture can and cannot anchor here
//!
//! `goose.zig` never parses the `goosePdu` itself — see its module doc
//! comment ("This file never encodes or decodes a `goosePdu`/`savPdu`") and
//! `SPEC.md`'s "The layering decision: no dependency on `iec61850`". So a real
//! capture anchors exactly what this module owns: the link-layer header
//! (EtherType / APPID / Length / Reserved 1 / Reserved 2), the APDU/extension
//! boundary `Length` derives, and — composed on top, never decoded — this
//! module's own security extension wrapping a genuine APDU.
//!
//! **None of the 493 real GOOSE frames surveyed across the five source
//! `.pcap` files carries an IEC 62351-6 security extension**: `Reserved 1`
//! and `Reserved 2` are `0x0000` in every one of them. That is itself the
//! anchored finding, not a gap in the search — it matches `SPEC.md`'s
//! "Third-party oracle" section, which already recorded that no IEC 61850
//! stack was available to test 62351-6 interoperability against. Real-world
//! GOOSE traffic essentially never turns the layer-2 security profile on;
//! these captures confirm the *header* half of that gap and leave the
//! *security extension's* wire shape exactly as documented: this module's own
//! model, composable over any caller-supplied APDU (real or synthetic).
//!
//! As a bonus — not a claim about `goose.zig`'s own scope — this file also
//! walks the real `goosePdu` content with this module's own `ber.zig` TLV
//! reader (`gocbRef`/`stNum`/`sqNum`/`allData` and friends). The semantic
//! `goosePdu` model belongs to the sibling `iec61850` module; what is being
//! anchored here is `ber.zig`'s definite-length BER reader against genuine
//! ASN.1 wire bytes, since `ber.zig` lives in *this* module.

const std = @import("std");
const testing = std.testing;
const goose = @import("goose.zig");
const ber = @import("ber.zig");

/// Number of real frames vendored below — a canary so a future edit can't
/// silently drop one without updating `../NOTICE` alongside it.
pub const vendored_frame_count = 3;

/// GE (General Electric) F650 protection relay, real GOOSE publication.
/// Source: cutaway-security/goosestalker `PCAPs/GOOSE.pcap`, frame 1 of 8 (the
/// other seven are the same publisher's unchanged heartbeat retransmissions).
/// No VLAN tag in the source capture. Bytes run from the EtherType field, per
/// this module's `parse` contract.
const frame_f650 = [_]u8{
    0x88, 0xb8, 0x00, 0x01, 0x00, 0x91, 0x00, 0x00, 0x00, 0x00, 0x61, 0x81,
    0x86, 0x80, 0x1a, 0x47, 0x45, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x46,
    0x36, 0x35, 0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x24, 0x47, 0x4f, 0x24,
    0x67, 0x63, 0x62, 0x30, 0x31, 0x81, 0x03, 0x00, 0x9c, 0x40, 0x82, 0x18,
    0x47, 0x45, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x46, 0x36, 0x35, 0x30,
    0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x24, 0x47, 0x4f, 0x4f, 0x53, 0x45, 0x31,
    0x83, 0x0b, 0x46, 0x36, 0x35, 0x30, 0x5f, 0x47, 0x4f, 0x4f, 0x53, 0x45,
    0x31, 0x84, 0x08, 0x38, 0x6e, 0xbb, 0xf3, 0x42, 0x17, 0x28, 0x0a, 0x85,
    0x01, 0x01, 0x86, 0x01, 0x0a, 0x87, 0x01, 0x00, 0x88, 0x01, 0x01, 0x89,
    0x01, 0x00, 0x8a, 0x01, 0x08, 0xab, 0x20, 0x83, 0x01, 0x00, 0x84, 0x03,
    0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83,
    0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03,
    0x03, 0x00, 0x00,
};

/// A mock four-bus/18-IED substation's `AA1C1Q01A1LD0` IED, real GOOSE
/// publication. Source: `PCAPs/Sample_File_GOOSE.pcap`, frame 1 of 451. The
/// source capture carries an IEEE 802.1Q VLAN tag between the MAC addresses
/// and the GOOSE EtherType; those 4 octets are stripped here, matching this
/// module's documented contract that the caller resolves the MAC domain
/// (VLAN included) before calling `parse`.
const frame_aa1_gcb_a = [_]u8{
    0x88, 0xb8, 0x30, 0x01, 0x00, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x61, 0x81,
    0xd8, 0x80, 0x1b, 0x41, 0x41, 0x31, 0x43, 0x31, 0x51, 0x30, 0x31, 0x41,
    0x31, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x24, 0x47, 0x4f,
    0x24, 0x67, 0x63, 0x62, 0x5f, 0x41, 0x81, 0x02, 0x3a, 0x98, 0x82, 0x20,
    0x41, 0x41, 0x31, 0x43, 0x31, 0x51, 0x30, 0x31, 0x41, 0x31, 0x4c, 0x44,
    0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x24, 0x49, 0x6e, 0x74, 0x65, 0x72,
    0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x41, 0x83, 0x0d, 0x49, 0x6e,
    0x74, 0x65, 0x72, 0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x41, 0x84,
    0x08, 0x48, 0x88, 0x90, 0xc1, 0x24, 0x00, 0x00, 0x27, 0x85, 0x03, 0x00,
    0x8f, 0x61, 0x86, 0x01, 0x00, 0x87, 0x01, 0x00, 0x88, 0x01, 0x01, 0x89,
    0x01, 0x00, 0x8a, 0x01, 0x19, 0xab, 0x66, 0x83, 0x01, 0x00, 0x83, 0x01,
    0x00, 0x83, 0x01, 0x00, 0x83, 0x01, 0x00, 0x83, 0x01, 0x00, 0x83, 0x01,
    0x00, 0x83, 0x01, 0x00, 0x84, 0x02, 0x06, 0x80, 0x84, 0x03, 0x03, 0x00,
    0x00, 0x84, 0x02, 0x06, 0x80, 0x84, 0x03, 0x03, 0x00, 0x00, 0x84, 0x02,
    0x06, 0x80, 0x84, 0x03, 0x03, 0x00, 0x00, 0x84, 0x02, 0x06, 0x00, 0x84,
    0x03, 0x03, 0x00, 0x00, 0x84, 0x02, 0x06, 0x40, 0x84, 0x03, 0x03, 0x00,
    0x00, 0x84, 0x02, 0x06, 0x40, 0x84, 0x03, 0x03, 0x00, 0x00, 0x84, 0x02,
    0x06, 0x40, 0x84, 0x03, 0x03, 0x00, 0x00, 0x84, 0x02, 0x06, 0x40, 0x84,
    0x03, 0x03, 0x00, 0x00, 0x84, 0x02, 0x06, 0x40, 0x84, 0x03, 0x03, 0x00,
    0x00,
};

/// The sibling IED `AA1C1Q05A1LD0` in the same mock substation. Source:
/// `PCAPs/Sample_File_MMS_and_GOOSE.pcap`, frame 39 of 301 (the first GOOSE
/// frame in a capture that interleaves GOOSE with MMS/TCP traffic).
/// VLAN-stripped as above.
const frame_aa1_gcb_a2 = [_]u8{
    0x88, 0xb8, 0x30, 0x01, 0x00, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x61, 0x81,
    0xd8, 0x80, 0x1b, 0x41, 0x41, 0x31, 0x43, 0x31, 0x51, 0x30, 0x35, 0x41,
    0x31, 0x4c, 0x44, 0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x24, 0x47, 0x4f,
    0x24, 0x67, 0x63, 0x62, 0x5f, 0x41, 0x81, 0x02, 0x3a, 0x98, 0x82, 0x20,
    0x41, 0x41, 0x31, 0x43, 0x31, 0x51, 0x30, 0x35, 0x41, 0x31, 0x4c, 0x44,
    0x30, 0x2f, 0x4c, 0x4c, 0x4e, 0x30, 0x24, 0x49, 0x6e, 0x74, 0x65, 0x72,
    0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x41, 0x83, 0x0d, 0x49, 0x6e,
    0x74, 0x65, 0x72, 0x6c, 0x6f, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x41, 0x84,
    0x08, 0x48, 0x80, 0x8d, 0x67, 0x54, 0x00, 0x00, 0x27, 0x85, 0x01, 0x73,
    0x86, 0x03, 0x02, 0x23, 0x27, 0x87, 0x01, 0x00, 0x88, 0x01, 0x05, 0x89,
    0x01, 0x00, 0x8a, 0x01, 0x19, 0xab, 0x66, 0x83, 0x01, 0x00, 0x83, 0x01,
    0x00, 0x83, 0x01, 0x00, 0x83, 0x01, 0x00, 0x83, 0x01, 0x00, 0x83, 0x01,
    0x00, 0x83, 0x01, 0x00, 0x84, 0x02, 0x06, 0x40, 0x84, 0x03, 0x03, 0x00,
    0x00, 0x84, 0x02, 0x06, 0x40, 0x84, 0x03, 0x03, 0x00, 0x00, 0x84, 0x02,
    0x06, 0x40, 0x84, 0x03, 0x03, 0x00, 0x00, 0x84, 0x02, 0x06, 0x80, 0x84,
    0x03, 0x03, 0x00, 0x00, 0x84, 0x02, 0x06, 0x80, 0x84, 0x03, 0x03, 0x00,
    0x00, 0x84, 0x02, 0x06, 0x40, 0x84, 0x03, 0x03, 0x00, 0x00, 0x84, 0x02,
    0x06, 0x40, 0x84, 0x03, 0x03, 0x00, 0x00, 0x84, 0x02, 0x06, 0x40, 0x84,
    0x03, 0x03, 0x00, 0x00, 0x84, 0x02, 0x06, 0x40, 0x84, 0x03, 0x03, 0x00,
    0x00,
};

/// A real, unauthenticated GOOSE frame carries no extension at all — there is
/// nothing for `Verifier` to check. `goose.verify` must say so explicitly
/// rather than silently treating "absent" as "fine".
fn expectNoExtension(frame_bytes: []const u8) !void {
    try testing.expectError(error.NoExtension, goose.verify(frame_bytes, .ed2020, .{
        .mac = .{ .algorithm = .hmac_sha256_128, .key = &.{0x00} },
    }));
}

test "real capture: GE F650 GOOSE — header fields, no extension, either profile agrees" {
    const f = try goose.parse(&frame_f650, .ed2020);
    try testing.expectEqual(@as(u16, goose.ether_type_goose), f.ether_type);
    try testing.expectEqual(@as(u16, 0x0001), f.appid);
    try testing.expectEqual(@as(u16, 145), f.length);
    try testing.expectEqual(@as(u16, 0), f.reserved1);
    try testing.expectEqual(@as(u16, 0), f.reserved2);
    try testing.expect(!f.hasExtension());
    try testing.expectEqual(@as(usize, 137), f.apdu.len);
    try testing.expectEqual(@as(u8, 0x61), f.apdu[0]); // goosePdu APPLICATION [1], constructed

    // Real Reserved fields are all-zero, so the 2007 header profile (which
    // reads the extension length from a different field) must agree there is
    // still no extension.
    const f_ts2007 = try goose.parse(&frame_f650, .ts2007);
    try testing.expect(!f_ts2007.hasExtension());
    try testing.expectEqualSlices(u8, f.apdu, f_ts2007.apdu);

    try expectNoExtension(&frame_f650);
}

test "real capture: AA1C1Q01A1LD0 GOOSE — header fields, no extension" {
    const f = try goose.parse(&frame_aa1_gcb_a, .ed2020);
    try testing.expectEqual(@as(u16, 0x3001), f.appid);
    try testing.expectEqual(@as(u16, 227), f.length);
    try testing.expectEqual(@as(u16, 0), f.reserved1);
    try testing.expectEqual(@as(u16, 0), f.reserved2);
    try testing.expect(!f.hasExtension());
    try testing.expectEqual(@as(usize, 219), f.apdu.len);
    try expectNoExtension(&frame_aa1_gcb_a);
}

test "real capture: AA1C1Q05A1LD0 GOOSE (from a mixed GOOSE+MMS capture) — header fields" {
    const f = try goose.parse(&frame_aa1_gcb_a2, .ed2020);
    try testing.expectEqual(@as(u16, 0x3001), f.appid);
    try testing.expectEqual(@as(u16, 227), f.length);
    try testing.expectEqual(@as(u16, 0), f.reserved1);
    try testing.expectEqual(@as(u16, 0), f.reserved2);
    try testing.expect(!f.hasExtension());
    try testing.expectEqual(@as(usize, 219), f.apdu.len);
    try expectNoExtension(&frame_aa1_gcb_a2);
}

// ── bonus: the real goosePdu content, walked with this module's own BER reader ──

const GoosePduHeader = struct {
    gocb_ref: []const u8,
    time_allowed_to_live: []const u8,
    dat_set: []const u8,
    go_id: []const u8,
    t: []const u8,
    st_num: []const u8,
    sq_num: []const u8,
    num_dataset_entries: u8,
    all_data: []const u8,
};

/// Not part of `goose.zig`'s public API — this module never models the
/// `goosePdu` (see the file doc comment). Written here only to drive
/// `ber.zig`'s reader over the real `goosePdu` bytes as an honest anchor of
/// that shared primitive; `iec61850` owns the real semantic decode.
fn decodeGoosePduHeader(apdu: []const u8) !GoosePduHeader {
    const outer = try ber.readTagged(apdu, 0x61); // goosePdu, APPLICATION [1]
    if (outer.encoded_len != apdu.len) return error.UnexpectedTrailer;

    var it = ber.iterate(outer.content);
    const gocb_ref = (try it.next()) orelse return error.Truncated; // [0]
    const time_allowed = (try it.next()) orelse return error.Truncated; // [1]
    const dat_set = (try it.next()) orelse return error.Truncated; // [2]
    const go_id = (try it.next()) orelse return error.Truncated; // [3]
    const t = (try it.next()) orelse return error.Truncated; // [4]
    const st_num = (try it.next()) orelse return error.Truncated; // [5]
    const sq_num = (try it.next()) orelse return error.Truncated; // [6]
    _ = (try it.next()) orelse return error.Truncated; // [7] simulation
    _ = (try it.next()) orelse return error.Truncated; // [8] confRev
    _ = (try it.next()) orelse return error.Truncated; // [9] ndsCom
    const num_entries = (try it.next()) orelse return error.Truncated; // [10]
    const all_data = (try it.next()) orelse return error.Truncated; // [11] SEQUENCE

    if (num_entries.content.len != 1) return error.Unexpected;
    return .{
        .gocb_ref = gocb_ref.content,
        .time_allowed_to_live = time_allowed.content,
        .dat_set = dat_set.content,
        .go_id = go_id.content,
        .t = t.content,
        .st_num = st_num.content,
        .sq_num = sq_num.content,
        .num_dataset_entries = num_entries.content[0],
        .all_data = all_data.content,
    };
}

/// Walks a decoded `allData` SEQUENCE and counts its direct children — every
/// element in the three vendored frames is a primitive `[3] BOOLEAN` or
/// `[4] Quality`, but this only counts siblings, exactly like `numDatSetEntries`
/// does, rather than asserting each element's own type.
fn countAllData(all_data: []const u8) !usize {
    var it = ber.iterate(all_data);
    var n: usize = 0;
    while (try it.next()) |_| n += 1;
    return n;
}

test "real capture: GE F650 goosePdu fields decode with this module's own BER reader" {
    const f = try goose.parse(&frame_f650, .ed2020);
    const h = try decodeGoosePduHeader(f.apdu);
    try testing.expectEqualStrings("GEDeviceF650/LLN0$GO$gcb01", h.gocb_ref);
    try testing.expectEqualStrings("GEDeviceF650/LLN0$GOOSE1", h.dat_set);
    try testing.expectEqualStrings("F650_GOOSE1", h.go_id);
    try testing.expectEqualSlices(u8, &.{0x01}, h.st_num); // stNum 1
    try testing.expectEqualSlices(u8, &.{0x0a}, h.sq_num); // sqNum 10
    try testing.expectEqual(@as(u8, 8), h.num_dataset_entries);
    try testing.expectEqual(@as(usize, 8), try countAllData(h.all_data));
}

test "real capture: AA1C1Q01A1LD0 goosePdu fields decode with this module's own BER reader" {
    const f = try goose.parse(&frame_aa1_gcb_a, .ed2020);
    const h = try decodeGoosePduHeader(f.apdu);
    try testing.expectEqualStrings("AA1C1Q01A1LD0/LLN0$GO$gcb_A", h.gocb_ref);
    try testing.expectEqualStrings("AA1C1Q01A1LD0/LLN0$InterlockingA", h.dat_set);
    try testing.expectEqualStrings("InterlockingA", h.go_id);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x8f, 0x61 }, h.st_num); // stNum 36705
    try testing.expectEqualSlices(u8, &.{0x00}, h.sq_num); // sqNum 0
    try testing.expectEqual(@as(u8, 25), h.num_dataset_entries);
    try testing.expectEqual(@as(usize, 25), try countAllData(h.all_data));
}

test "real capture: AA1C1Q05A1LD0 goosePdu fields decode with this module's own BER reader" {
    const f = try goose.parse(&frame_aa1_gcb_a2, .ed2020);
    const h = try decodeGoosePduHeader(f.apdu);
    try testing.expectEqualStrings("AA1C1Q05A1LD0/LLN0$GO$gcb_A", h.gocb_ref);
    try testing.expectEqualStrings("AA1C1Q05A1LD0/LLN0$InterlockingA", h.dat_set);
    try testing.expectEqualStrings("InterlockingA", h.go_id);
    try testing.expectEqualSlices(u8, &.{0x73}, h.st_num); // stNum 115
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x23, 0x27 }, h.sq_num); // sqNum 140071
    try testing.expectEqual(@as(u8, 25), h.num_dataset_entries);
    try testing.expectEqual(@as(usize, 25), try countAllData(h.all_data));
}

// ── composed with this module's own security extension ─────────────────────

test "real capture: a genuine APDU wrapped in this module's own HMAC extension round-trips and rejects tampering" {
    // The real captured APDU is opaque to this module either way -- `build`
    // never inspects it, exactly as it never would a synthetic one.
    const parsed = try goose.parse(&frame_aa1_gcb_a, .ed2020);
    const key = [_]u8{0x77} ** 20;
    const verifier: goose.Verifier = .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &key } };

    var out: [512]u8 = undefined;
    const wrapped = try goose.build(&out, .{
        .appid = parsed.appid,
        .apdu = parsed.apdu,
        .auth = .{ .key_id = 0x2026_08, .tag = &.{} },
    }, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &key } });

    const r = try goose.verify(wrapped, .ed2020, verifier);
    try testing.expectEqualSlices(u8, parsed.apdu, r.frame.apdu);
    try testing.expect(r.frame.hasExtension());
    try testing.expectEqual(@as(u32, 0x2026_08), r.auth.key_id);

    // Tamper a byte inside the *real* captured APDU content -- the gocbRef
    // text, specifically -- and the wrapper must still catch it.
    var tampered: [512]u8 = undefined;
    @memcpy(tampered[0..wrapped.len], wrapped);
    tampered[goose.apdu_offset + 5] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, goose.verify(tampered[0..wrapped.len], .ed2020, verifier));
}

test "canary: exactly `vendored_frame_count` real GOOSE frames are vendored" {
    const frames = [_][]const u8{ &frame_f650, &frame_aa1_gcb_a, &frame_aa1_gcb_a2 };
    try testing.expectEqual(vendored_frame_count, frames.len);
}
