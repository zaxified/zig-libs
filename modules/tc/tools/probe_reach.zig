// SPDX-License-Identifier: MIT
//! Is an out-of-range `cell_log`, `mtu` or `kind` reachable through the PUBLIC
//! API, and what happens when it is?
//!
//! Run it (from the repository root):
//!
//!     scripts/capped zig test -OReleaseSafe --cache-dir .zig-cache \
//!       --dep tc -Mroot=modules/tc/tools/probe_reach.zig \
//!       --dep netlink --dep testkit -Mtc=modules/tc/src/root.zig \
//!       -Mnetlink=modules/netlink/src/root.zig \
//!       -Mtestkit=modules/testkit/src/root.zig
//!
//! ⚠ This probe is written the other way up from the audit version it replaces,
//! and the reason is worth keeping. When the 2026-09-04 audit wrote it, the
//! guards did not exist: a forced `cell_log` of 32 reached `@intCast` to `u5`
//! and ABORTED, so "the test aborts" *was* the finding and the cases needed no
//! assertion at all — they simply built a request and freed it.
//!
//! F2/F7 then closed that (`ratespec.max_cell_log`, `checkCellLog`). Measured
//! 2026-09-16 against the live module: the same four cases now return
//! `InvalidCellLog` ×3 and `OptionsTooLong` ×1, so the probe failed 4 of 7 —
//! **every failure being the fix working.** An instrument that fires on every
//! healthy run is no better than one that cannot fire at all; it just fails in
//! the opposite direction. So each case now names the error the guard owes, and
//! a case goes RED only if the guard is gone.
const std = @import("std");
const tc = @import("tc");
const testing = std.testing;
const ps = tc.ratespec.golden_psched;
const gpa = std.testing.allocator;

const target: tc.message.ClassTarget = .{
    .ifindex = 1,
    .handle = tc.Handle.init(1, 0x10),
    .parent = tc.Handle.init(1, 0),
};

// ── forced cell shifts: one legal, three past `ratespec.max_cell_log` ────────

test "REACH: a legal forced shift (cell_log = 3) still builds" {
    const req = try tc.message.buildClassSet(gpa, 1, .add, target, .{
        .htb = .{ .rate = 125_000, .cell_log = 3 },
    }, ps);
    defer gpa.free(req);
    try testing.expect(req.len > 2000);
}

test "REACH: HtbClass.cell_log = 32 is refused, not @intCast into a u5" {
    try testing.expectError(error.InvalidCellLog, tc.message.buildClassSet(gpa, 1, .add, target, .{
        .htb = .{ .rate = 125_000, .cell_log = 32 },
    }, ps));
}

test "REACH: Tbf.cell_log = 200 is refused" {
    try testing.expectError(error.InvalidCellLog, tc.message.buildQdiscSet(gpa, 1, .add, .{ .ifindex = 1 }, .{
        .tbf = .{ .rate = 125_000, .burst = 1024, .limit = 4096, .cell_log = 200 },
    }, ps));
}

test "REACH: Police.cell_log = 64 is refused on the filter path too" {
    const acts = [_]tc.ActionSpec{.{ .police = .{ .rate = 125_000, .burst = 1024, .cell_log = 64 } }};
    try testing.expectError(error.InvalidCellLog, tc.message.buildFilterSetWith(gpa, 1, .add, .{
        .ifindex = 1,
        .parent = tc.Handle.init(1, 0),
        .prio = 1,
        .eth_type = tc.filter.ETH_P.IP,
    }, .{ .u32 = .{ .actions = &acts } }, ps));
}

// ── an mtu large enough to overflow the rate table's last entry ──────────────

test "REACH: HtbClass.mtu = 2^31 saturates the rate table instead of wrapping it" {
    // ⚠ The audit called this one "silently wraps the last table entry to 0".
    // It does not any more, and the name is not a detail: measured 2026-09-16
    // the last two entries are both 4294967295, i.e. the arithmetic saturates,
    // which is what `ratespec`'s doc comment promises. A table that DECREASES
    // is the defect; the test asserts that and nothing about how it is spelled.
    const req = try tc.message.buildClassSet(gpa, 1, .add, target, .{
        .htb = .{ .rate = 125_000, .mtu = 2147483648 },
    }, ps);
    defer gpa.free(req);
    const rtab_end = req.len - 1028; // CTAB is the last attribute (1028 B)
    const last = std.mem.readInt(u32, req[rtab_end - 4 ..][0..4], .little);
    const prev = std.mem.readInt(u32, req[rtab_end - 8 ..][0..4], .little);
    try testing.expect(last >= prev);
}

// ── an over-long caller-supplied `kind` ─────────────────────────────────────

test "REACH: a 100-byte raw kind is accepted and put on the wire" {
    // Recorded, not asserted as desirable: nothing enforces IFNAMSIZ on the
    // public `raw` specs, so a caller can name a 100-byte qdisc kind and the
    // kernel is the one that says no. Pinned so a future change is deliberate.
    const k = [_]u8{'x'} ** 100;
    const req = try tc.message.buildQdiscSet(gpa, 1, .add, .{ .ifindex = 1 }, .{
        .raw = .{ .kind = &k },
    }, ps);
    defer gpa.free(req);
    try testing.expectEqual(@as(usize, 148), req.len);
}

test "REACH: a 70000-byte raw kind returns an error rather than reaching unreachable" {
    // `message.zig` used to assert `error.AttrTooLong => unreachable` here on
    // the grounds that "kind strings are <= IFNAMSIZ", which the public `raw`
    // spec never enforced. It is a returned error now.
    const k = try gpa.alloc(u8, 70_000);
    defer gpa.free(k);
    @memset(k, 'x');
    try testing.expectError(error.OptionsTooLong, tc.message.buildQdiscSet(gpa, 1, .add, .{ .ifindex = 1 }, .{
        .raw = .{ .kind = k },
    }, ps));
}
