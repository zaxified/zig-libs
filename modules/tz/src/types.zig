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

pub const Zone = struct {
    name: []const u8,
    /// State before the first transition (the state at the epoch in the
    /// default table; the zone's first, local-mean-time state in the full one).
    init_off: i32,
    init_dst: bool,
    /// Offset of the initial abbreviation in `abbrevs`.
    init_abbr: u16 = 0,
    trans: []const Transition,
    /// The POSIX-TZ footer rule, applied past the last explicit transition.
    posix: []const u8,
    /// `posix` parsed at generation time. Null for a zone built by hand (a
    /// test, a caller's own footer): `offsetAt` then parses `posix` per call.
    footer: ?*const Footer = null,
    /// For a link (an alias such as `US/Eastern`) the name of the zone it
    /// points to (`America/New_York`); null for a canonical zone.
    canonical: ?[]const u8 = null,
};
