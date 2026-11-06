// SPDX-License-Identifier: MIT

//! Helpers shared by `Manager` (root.zig) and `CookieManager`
//! (cookiestore.zig): the created/remember word both record formats carry,
//! and the cookie `Max-Age` of an idle window. Not part of the public API.

const std = @import("std");
const root = @import("root.zig");

// Bit 63 of the stored `created_ns` word is the session's remember-me flag
// (`Session.rememberMe`); the timestamp itself is the low 63 bits read as a
// signed (two's complement) 63-bit number, so any clock value in
// [-2^62, 2^62) -- about +-146 years of nanoseconds, a negative one included --
// round-trips exactly. Records written before the flag existed have bit 63
// clear for every non-negative time, i.e. read as "flag off" and unchanged.
pub const remember_bit: u64 = 1 << 63;
pub const created_min: i64 = -(1 << 62);
pub const created_max: i64 = (1 << 62) - 1;

pub fn encodeCreated(created: i64, remember: bool) u64 {
    const c: u64 = @bitCast(std.math.clamp(created, created_min, created_max));
    return (c & ~remember_bit) | (if (remember) remember_bit else 0);
}

pub const Created = struct { created: i64, remember: bool };

pub fn decodeCreated(word: u64) Created {
    // Sign-extend bit 62 into bit 63.
    const low = word & ~remember_bit;
    const ext = if (low & (1 << 62) != 0) low | remember_bit else low;
    return .{ .created = @bitCast(ext), .remember = word & remember_bit != 0 };
}

pub fn maxAgeSeconds(idle_ns: i64) i64 {
    if (idle_ns <= 0) return root.default_absolute_timeout_ns / std.time.ns_per_s;
    // At least 1: `Max-Age=0` would make the browser drop the cookie at once.
    return @max(1, @divTrunc(idle_ns, std.time.ns_per_s));
}
