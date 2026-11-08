// SPDX-License-Identifier: MIT

//! Length-prefixed field framing shared by the threshold_ecdsa message codecs:
//! a 4-byte big-endian length followed by that many bytes.

const std = @import("std");

/// Append `data` to `list` as a 4-byte big-endian length followed by the bytes.
/// `data.len` must fit in a `u32` (every caller passes a protocol field of at
/// most a few KiB).
pub fn appendLenPrefixed(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error!void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try list.appendSlice(allocator, &len_buf);
    try list.appendSlice(allocator, data);
}

/// Read one length-prefixed field at `offset.*` and advance `offset`.
/// `error.InvalidEncoding` when the prefix or the body runs past the end of
/// `bytes`. Subtractions, not `offset + len`: a `u32` length added to a `usize`
/// offset wraps on 32-bit targets and would pass the bound.
pub fn readLenPrefixed(bytes: []const u8, offset: *usize) error{InvalidEncoding}![]const u8 {
    if (bytes.len - offset.* < 4) return error.InvalidEncoding;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len - offset.* < len) return error.InvalidEncoding;
    const out = bytes[offset.*..][0..len];
    offset.* += len;
    return out;
}
