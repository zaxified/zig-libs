// SPDX-License-Identifier: MIT
//! The record types of the generated zone tables (`tz_data.zig`, and the
//! pre-1970 variant `tz_data_full.zig`): hand-written and shared, so both
//! files hold the same `Zone` and the lookup code works on either.

const posix = @import("posix.zig");

pub const Footer = posix.Footer;

/// One change of a zone's UTC offset, DST flag or abbreviation. At `ts` the
/// zone starts showing `off`/`dst`/`abbr`.
pub const Transition = struct {
    ts: i64,
    off: i32,
    dst: bool,
    /// Byte offset of the abbreviation (`CET`) in the table's `abbrevs`
    /// string (NUL-terminated entries; offset 0 is the empty string).
    abbr: u16 = 0,
};

/// A `Transition` as the shipped tables store it, in 8 bytes instead of 16:
/// `ts` in whole seconds as a `u32` (1970 to 2106; every shipped change after
/// the epoch lies before 2088, and the generator refuses one that does not),
/// `off` (20 bits signed, +-145 h), `dst` and `abbr` (11 bits: the table's
/// `abbrevs` stay under 2048 bytes) packed into one word. Build one with
/// `make`, read it back with `unpack`.
pub const Compact = extern struct {
    ts: u32,
    info: u32,

    const off_bits = 20;
    const abbr_bits = 11;

    /// The largest `abbr` a `Compact` holds.
    pub const max_abbr: u16 = (1 << abbr_bits) - 1;

    pub fn make(comptime ts: u32, comptime off: i32, comptime dst: bool, comptime abbr: u16) Compact {
        if (off < -(1 << (off_bits - 1)) or off >= (1 << (off_bits - 1))) @compileError("tz: offset does not fit a Compact");
        if (abbr > max_abbr) @compileError("tz: abbreviation index does not fit a Compact");
        const o: u32 = @as(u20, @bitCast(@as(i20, @intCast(off))));
        return .{ .ts = ts, .info = o | (@as(u32, @intFromBool(dst)) << off_bits) | (@as(u32, abbr) << (off_bits + 1)) };
    }

    pub fn unpack(c: Compact) Transition {
        return .{
            .ts = c.ts,
            .off = @as(i20, @bitCast(@as(u20, @truncate(c.info)))),
            .dst = (c.info >> off_bits) & 1 == 1,
            .abbr = @intCast(c.info >> (off_bits + 1)),
        };
    }
};

pub const Zone = struct {
    name: []const u8,
    /// State before the first transition (the state at the epoch in the
    /// default table; the zone's first, local-mean-time state in the full one).
    init_off: i32,
    init_dst: bool,
    /// Offset of the initial abbreviation in `abbrevs`.
    init_abbr: u16 = 0,
    /// The changes from 1970 to 2037 in the shipped 8-byte form, ascending.
    trans: []const Compact = &.{},
    /// Changes before `trans[0]`, ascending, in the full 16-byte form: the
    /// pre-1970 history of a `tz.full` zone, or all the changes of a zone
    /// built by hand (`trans` empty; `ts` is an `i64` there). Empty for a
    /// default-table zone.
    pre: []const Transition = &.{},
    /// The POSIX-TZ footer rule, applied past the last explicit transition.
    posix: []const u8,
    /// `posix` parsed at generation time. Null for a zone built by hand (a
    /// test, a caller's own footer): `offsetAt` then parses `posix` per call;
    /// set it from `tz.parseFooter(posix)` to parse once.
    footer: ?*const Footer = null,
    /// For a link (an alias such as `US/Eastern`) the name of the zone it
    /// points to (`America/New_York`); null for a canonical zone.
    canonical: ?[]const u8 = null,

    /// How many changes the zone's table holds: `pre`, then `trans`.
    pub fn len(z: *const Zone) usize {
        return z.pre.len + z.trans.len;
    }

    /// The `i`-th change (`i < len()`), in ascending time order.
    pub fn at(z: *const Zone, i: usize) Transition {
        return if (i < z.pre.len) z.pre[i] else z.trans[i - z.pre.len].unpack();
    }

    /// The time of the `i`-th change.
    pub fn tsAt(z: *const Zone, i: usize) i64 {
        return if (i < z.pre.len) z.pre[i].ts else z.trans[i - z.pre.len].ts;
    }
};
