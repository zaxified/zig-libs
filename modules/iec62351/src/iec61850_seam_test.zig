// SPDX-License-Identifier: MIT

//! The seam with the sibling `iec61850` GOOSE decoder (A1 finding N1). This
//! module secures frames that `iec61850` encodes and a subscriber decodes, so
//! the only honest test of the seam runs the sibling's REAL decoder on a frame
//! this module built. Before the fix that decoder accepted the frame, returned
//! the PDU with the IEC 62351-6 extension glued onto it, and decoded stNum/
//! sqNum from it without any sign that authentication existed.
//!
//! `iec61850` is a test-only dependency: neither module depends on the other.

const std = @import("std");
const testing = std.testing;
const iec61850 = @import("iec61850");
const goose = @import("goose.zig");

test "iec61850's GOOSE decoder refuses a frame this module secured, and decodeSecured splits it exactly" {
    // A real goosePdu from the sibling's own encoder.
    const p = iec61850.goose.Pdu{
        .gocb_ref = "LD/LLN0$GO$gcb",
        .time_allowed_to_live_ms = 2000,
        .dat_set = "LD/LLN0$ds",
        .go_id = "gcb",
        .t = iec61850.UtcTime.fromMillis(1_700_000_000_000, 10),
        .st_num = 5,
        .sq_num = 3,
        .test_mode = false,
        .conf_rev = 1,
        .nds_com = false,
        .num_dat_set_entries = 1,
        .all_data = &.{},
    };
    var pbuf: [256]u8 = undefined;
    const apdu = try p.encode(&[_][]const u8{&[_]u8{ 0x83, 0x01, 0x01 }}, &pbuf); // boolean TRUE

    const key = [_]u8{0x42} ** 32;
    var out: [512]u8 = undefined;
    const secured = try goose.build(&out, .{
        .appid = 0x3001,
        .apdu = apdu,
        .auth = .{ .key_id = 1, .tag = &.{} },
    }, .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &key } });
    const parsed = try goose.parse(secured, .ed2020);
    try testing.expect(parsed.hasExtension());

    // `iec61850` decodes from the MAC header; this module's frame starts at the EtherType.
    var wire: [600]u8 = undefined;
    @memcpy(wire[0..6], &[_]u8{ 0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01 });
    @memcpy(wire[6..12], &[_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 });
    @memcpy(wire[12..][0..secured.len], secured);
    const frame = wire[0 .. 12 + secured.len];

    try testing.expectError(error.SecurityExtensionPresent, iec61850.goose.Frame.decode(frame));

    const f = try iec61850.goose.Frame.decodeSecured(frame);
    try testing.expectEqualSlices(u8, parsed.apdu, f.pdu);
    try testing.expectEqualSlices(u8, parsed.extension, f.extension);
    const pdu = try iec61850.goose.Pdu.decode(f.pdu);
    try testing.expectEqual(@as(u32, 5), pdu.st_num);

    // And the same octets still authenticate here.
    const verifier: goose.Verifier = .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &key } };
    _ = try goose.verify(secured, .ed2020, verifier);
}
