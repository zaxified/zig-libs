// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): what a scheduling consumer uses of tz, a zone
//! looked up by name from the command line and its offset and abbreviation at one instant. Built at
//! ReleaseSmall by `scripts/checks/small-sizes.sh` under `-Dprofile=default` (every zone) and under
//! `-Dprofile=small` together with the explicit knob `-Dtz-zones=Europe/Prague,America/New_York,UTC`
//! (the profile itself leaves tz alone); the difference is the zone data left out, held to its floor in
//! `scripts/checks/small-size-expected.tsv`.
const std = @import("std");
const tz = @import("tz");

pub fn main(init: std.process.Init) !void {
    var it = init.minimal.args.iterate();
    _ = it.next();
    const name = it.next() orelse return error.MissingZoneName;
    const zone = tz.find(name) orelse return error.UnknownZone;
    const o = tz.offsetAt(zone, 1_700_000_000);
    std.process.exit(@intCast(@as(u32, @bitCast(o.off)) & 0x7f | @intFromBool(o.dst)));
}
