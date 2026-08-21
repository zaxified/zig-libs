// SPDX-License-Identifier: MIT

//! What a neighbour-discovery consumer does with `l2disco`: take the bytes a
//! switch just sent, decide what protocol they are, and print who is on the
//! other end of the wire.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const l2disco = @import("l2disco");

/// One LLDPDU as a switch emits it: the three mandatory TLVs (Chassis ID,
/// Port ID, TTL) followed by System Name and the end-of-PDU marker.
const lldp_frame = [_]u8{
    0x02, 0x07, 0x04, 0x00, 0x1b, 0x21, 0x3f, 0x9c, 0x8a, // Chassis ID: MAC
    0x04, 0x07, 0x03, 0x47, 0x69, 0x30, 0x2f, 0x31, 0x37, // Port ID: "Gi0/17"
    0x06, 0x02, 0x00, 0x78, // TTL: 120 s
    0x0a, 0x08, 0x73, 0x77, 0x2d, 0x61, 0x63, 0x63, 0x2d, 0x31, // System Name
    0x00, 0x00, // End of LLDPDU
};

pub fn main() !void {
    // Strict parse: an unparseable optional TLV is a rejected frame, which is
    // what a consumer feeding an inventory wants.
    const pdu = l2disco.Lldpdu.parse(&lldp_frame, .{}) catch |err| switch (err) {
        // The error set has to be nameable from out here to be handled at all.
        error.BadTlvLength, error.TruncatedTlv => {
            std.debug.print("malformed LLDPDU, dropping\n", .{});
            return;
        },
        else => return err,
    };

    std.debug.print("neighbour ttl={d}s", .{pdu.ttl_s});
    if (pdu.system_name) |name| std.debug.print(" name={s}", .{name});
    std.debug.print("\n", .{});

    // Tolerant parse is the other posture: keep the frame, count what was
    // skipped. A monitoring consumer wants the neighbour even from a switch
    // whose optional TLVs are wrong.
    const lenient = try l2disco.Lldpdu.parse(&lldp_frame, .{ .tolerant_optionals = true });
    std.debug.print("tolerant parse skipped {d} optional TLV(s)\n", .{lenient.skipped_optionals});

    // A MAC formats through the module's own type, not by hand.
    const mac: l2disco.Mac = .{ .octets = .{ 0x00, 0x1b, 0x21, 0x3f, 0x9c, 0x8a } };
    var mac_buf: [l2disco.Mac.text_len]u8 = undefined;
    std.debug.print("chassis mac={s}\n", .{mac.format(&mac_buf)});
}
