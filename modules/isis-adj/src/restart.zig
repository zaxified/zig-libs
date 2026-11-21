// SPDX-License-Identifier: MIT

//! The Restart TLV (type 211) of RFC 5306 (IS-IS restart signalling) and the
//! helper state both adjacency machines keep.
//!
//! Value layout: a flags octet (RR = 0x01 restart request, RA = 0x02 restart
//! acknowledgement, SA = 0x04 suppress adjacency advertisement), then, only
//! when RA is set, the remaining holding time (2 octets, seconds) and the
//! System ID of the restarting neighbour the RA refers to (6 octets here).
//! Well-formed lengths are therefore 1, 3 and 9. RFC 5306 section 3.2 lets
//! older implementations omit the neighbour id when RA is set (length 3); a
//! router expecting an RA on a LAN then takes it to be about itself.

const std = @import("std");

pub const tlv_code: u8 = 211;

pub const flag_rr: u8 = 0x01;
pub const flag_ra: u8 = 0x02;
pub const flag_sa: u8 = 0x04;

pub const DecodeError = error{BadLength};

pub const Restart = struct {
    /// Restart Request: the sender is restarting and asks its neighbours to
    /// keep the adjacency.
    rr: bool = false,
    /// Restart Acknowledgement: the sender is a helper and confirms.
    ra: bool = false,
    /// Suppress Adjacency advertisement: the sender (a router starting up)
    /// asks the neighbour not to advertise the adjacency in its LSPs yet.
    sa: bool = false,
    /// Remaining holding time of the adjacency at the helper, in the
    /// caller's time unit capped to 16 bits; present with RA.
    remaining_time: ?u16 = null,
    /// The restarting neighbour an RA is about (LAN circuits).
    neighbor_id: ?[6]u8 = null,

    pub const max_len = 9;

    pub fn encode(self: Restart, buf: *[max_len]u8) []const u8 {
        buf[0] = (if (self.rr) flag_rr else 0) | (if (self.ra) flag_ra else 0) | (if (self.sa) flag_sa else 0);
        var n: usize = 1;
        if (self.remaining_time) |t| {
            std.mem.writeInt(u16, buf[1..3], t, .big);
            n = 3;
            if (self.neighbor_id) |id| {
                @memcpy(buf[3..9], &id);
                n = 9;
            }
        }
        return buf[0..n];
    }

    pub fn decode(value: []const u8) DecodeError!Restart {
        if (value.len != 1 and value.len != 3 and value.len != 9) return error.BadLength;
        var r: Restart = .{
            .rr = value[0] & flag_rr != 0,
            .ra = value[0] & flag_ra != 0,
            .sa = value[0] & flag_sa != 0,
        };
        if (value.len >= 3) r.remaining_time = std.mem.readInt(u16, value[1..3], .big);
        if (value.len == 9) r.neighbor_id = value[3..9].*;
        return r;
    }
};

/// What a helper keeps per adjacency (RFC 5306 section 3.2.1 and 3.2.2).
pub const HelperState = struct {
    /// Set by the first RR IIH of an Up adjacency; cleared by an IIH with RR
    /// clear and whenever the adjacency leaves Up. It has no effect on
    /// adjacency transitions, only on the hold refresh (see below).
    restart_mode: bool = false,
    /// The neighbour's last SA: while set, the adjacency is not advertised
    /// and not used in SPF.
    suppress: bool = false,
};

const testing = std.testing;

test "Restart TLV: the three legal lengths round-trip and the rest are refused" {
    var buf: [Restart.max_len]u8 = undefined;
    const cases = [_]Restart{
        .{ .rr = true },
        .{ .sa = true, .rr = true },
        .{ .ra = true, .remaining_time = 27 },
        .{ .ra = true, .remaining_time = 65535, .neighbor_id = .{ 1, 2, 3, 4, 5, 6 } },
    };
    const lens = [_]usize{ 1, 1, 3, 9 };
    for (cases, lens) |c, l| {
        const v = c.encode(&buf);
        try testing.expectEqual(l, v.len);
        try testing.expectEqual(c, try Restart.decode(v));
    }
    try testing.expectEqual(@as(u8, 0x05), (Restart{ .rr = true, .sa = true }).encode(&buf)[0]);
    for ([_]usize{ 0, 2, 4, 8, 10 }) |n| {
        const junk: [10]u8 = @splat(0);
        try testing.expectError(error.BadLength, Restart.decode(junk[0..n]));
    }
}
