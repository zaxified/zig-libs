// SPDX-License-Identifier: MIT

//! What a scheduling / reporting consumer does with `tz`: resolve an IANA
//! zone by name and ask for the UTC offset at a specific instant, exercising
//! the three interesting cases the module documents — a DST transition
//! (right at the boundary instant, not somewhere in the middle of the
//! season), a pre-1970 date served only by the zone's `init_off`/`init_dst`
//! fallback (the pinned table carries no transitions before 1970), and an
//! unknown zone name.
//!
//! External judge: the system `zdump -v Europe/Prague` (real IANA tzdata),
//! independent of this module's own generated table and its own test suite:
//!
//!   Europe/Prague  Sun Mar 31 00:59:59 2024 UT = ... CET  isdst=0 gmtoff=3600
//!   Europe/Prague  Sun Mar 31 01:00:00 2024 UT = ... CEST isdst=1 gmtoff=7200
//!
//! and, for the pre-1970 case, that `zdump` shows Prague settled on constant
//! CET (+3600, no DST) from the 1949 autumn transition through the 1970
//! spring one this module's pinned table starts recording — so any instant
//! in that gap (1960 here) must read back +3600 with no DST from `init_off`.

const std = @import("std");
const tz = @import("tz");

pub fn main() !void {
    const prague = tz.find("Europe/Prague").?;

    // The exact instant a DST transition takes effect (not an arbitrary
    // point well inside the season) — the boundary `offsetAt`'s binary
    // search actually has to get right. 2024-03-31T01:00:00Z is when
    // Europe/Prague switches from CET to CEST; zdump confirms both sides.
    const before_transition = 1711846799; // 2024-03-31T00:59:59Z
    const at_transition = 1711846800; // 2024-03-31T01:00:00Z

    const cet = tz.offsetAt(prague, before_transition);
    const cest = tz.offsetAt(prague, at_transition);
    std.debug.print("Europe/Prague {d}: off={d}s dst={}\n", .{ before_transition, cet.off, cet.dst });
    std.debug.print("Europe/Prague {d}: off={d}s dst={}\n", .{ at_transition, cest.off, cest.dst });
    if (cet.off != 3600 or cet.dst) return error.UnexpectedCet;
    if (cest.off != 7200 or !cest.dst) return error.UnexpectedCest;

    // A pre-1970 instant: the pinned table only carries transitions from
    // 1970 onward (SPEC.md), so this falls back to `init_off`/`init_dst`.
    // zdump shows Prague held constant CET, no DST, from the 1949-10-02
    // transition all the way to the first 1970 one — 1960-06-15 sits well
    // inside that gap, so the fallback value has to agree with the real
    // historical record, not just be internally consistent.
    const historical = -301233600; // 1960-06-15T12:00:00Z
    const pre1970 = tz.offsetAt(prague, historical);
    std.debug.print("Europe/Prague {d} (pre-1970 fallback): off={d}s dst={}\n", .{ historical, pre1970.off, pre1970.dst });
    if (pre1970.off != 3600 or pre1970.dst) return error.UnexpectedHistoricalOffset;

    // Unknown zone name: `find` is the module's only fallible-shaped entry
    // point, and it reports failure as `null` rather than an error union —
    // the module has no allocation and no other way to fail (see SPEC.md's
    // threat model: "no untrusted-input attack surface"), so there is no
    // `error.Foo` to name here.
    if (tz.find("Not/AZone") != null) return error.UnexpectedZoneFound;
    std.debug.print("unknown zone \"Not/AZone\": correctly not found\n", .{});
}
