// SPDX-License-Identifier: MIT
//! Opt-in profile of the F7 finding: `interfacesWithSrm`/`srmIterator`/
//! `ssnIterator` used to be a full `self.map.iterator()` scan **per call**,
//! even when nothing on that circuit was flagged. Fixed by giving each
//! interface its own SRM/SSN queue (`store.zig`'s `srm_queue`/`ssn_queue`) so
//! those calls read `O(#queued)`/`O(interface_count)` instead of `O(n)`. Off
//! by default (`error.SkipZigTest`); run it with:
//!
//!   ISIS_LSDB_BENCH=1 scripts/capped zig build test-isis-lsdb -Doptimize=ReleaseFast
//!
//! **Sizing.** `default_capacity` (4096) distinct small LSPs — a few hundred
//! KB total, nothing close to the memory an over-eager benchmark has OOM-
//! killed this host with before. Run under `scripts/capped`.

const std = @import("std");
const root = @import("root.zig");
const isis = @import("isis");
const Lsdb = root.Lsdb;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

const n_entries: usize = 4096;
const interface_count: u8 = 4;

fn buildLsp(buf: []u8, sys_id: u32, seq: u32) []const u8 {
    var sys: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, sys[2..6], sys_id, .big);
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, 0 },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finishStamped();
}

/// Fill the store to `n_entries`, all arrived on iface 0 (so SRM ends up
/// queued on ifaces {1,2,3}), then drain every queue so the store is
/// *idle* — the case the finding calls out explicitly ("even when nothing
/// is queued").
fn buildIdleStore(alloc: std.mem.Allocator) !Lsdb {
    var db = Lsdb.init(alloc, .{
        .local_system_id = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        .interface_count = interface_count,
        .capacity = n_entries,
    });
    var buf: [128]u8 = undefined;
    for (0..n_entries) |i| {
        _ = try db.insert(buildLsp(&buf, @intCast(i), 1), 0, 0);
    }
    var iface: u8 = 0;
    while (iface < interface_count) : (iface += 1) {
        var it = db.srmIterator(iface);
        var ids: [n_entries]root.LspId = undefined;
        var m: usize = 0;
        while (it.next()) |item| : (m += 1) ids[m] = item.lsp_id;
        for (ids[0..m]) |id| db.clearSrm(id, iface);
        var it2 = db.ssnIterator(iface);
        m = 0;
        while (it2.next()) |item| : (m += 1) ids[m] = item.lsp_id;
        for (ids[0..m]) |id| db.clearSsn(id, iface);
    }
    return db;
}

fn timeCall(comptime f: anytype, args: anytype, iters: usize) u64 {
    const t0 = nowNs();
    for (0..iters) |_| std.mem.doNotOptimizeAway(@call(.auto, f, args));
    return (nowNs() - t0) / iters;
}

fn callInterfacesWithSrm(db: *const Lsdb) root.InterfaceSet {
    return db.interfacesWithSrm();
}

fn callDrainSrmIterator(db: *const Lsdb, iface: u8) usize {
    var it = db.srmIterator(iface);
    var n: usize = 0;
    while (it.next()) |_| n += 1;
    return n;
}

test "bench (opt-in via ISIS_LSDB_BENCH): F7 flooding-flag query cost, idle and busy" {
    if (@import("builtin").target.os.tag == .windows or std.testing.environ.getPosix("ISIS_LSDB_BENCH") == null) return error.SkipZigTest;

    // NOT std.testing.allocator: a DebugAllocator's per-allocation bookkeeping
    // would dwarf the O(n) vs O(#queued) difference this bench exists to show.
    const gpa = std.heap.smp_allocator;

    var db = try buildIdleStore(gpa);
    defer db.deinit();

    const iters: usize = 2000;

    std.debug.print("\nisis-lsdb: F7 flooding-flag query cost (n = {d} LSPs, {d} interfaces)\n", .{ n_entries, interface_count });

    // 1) interfacesWithSrm() on a fully idle store — the case the finding
    //    calls out: "even when nothing is queued". Was O(n) (scan every
    //    entry's bitset); now O(interface_count).
    const idle_union_ns = timeCall(callInterfacesWithSrm, .{&db}, iters);
    std.debug.print("  interfacesWithSrm(), idle (0 queued): {d} ns/call\n", .{idle_union_ns});

    // 2) srmIterator(iface) drained on an idle circuit — was O(n) to find
    //    nothing; now O(1) (empty queue).
    const idle_iter_ns = timeCall(callDrainSrmIterator, .{ &db, @as(u8, 0) }, iters);
    std.debug.print("  srmIterator(iface).drain(), idle (0 queued): {d} ns/call\n", .{idle_iter_ns});

    // 3) Busy case: a realistic small burst — 8 of the 4096 LSPs re-flagged
    //    on one circuit (e.g. a link flap) — was O(n) to find 8; now O(8).
    var buf: [128]u8 = undefined;
    for (0..8) |i| {
        const wire = buildLsp(&buf, @intCast(i), 2); // higher seq -> newer
        _ = try db.insert(wire, 1, 0); // arrives on iface 1 -> SRM on {0,2,3}
    }
    const busy_iter_ns = timeCall(callDrainSrmIterator, .{ &db, @as(u8, 0) }, iters);
    std.debug.print("  srmIterator(iface).drain(), busy (8 of {d} queued): {d} ns/call\n", .{ n_entries, busy_iter_ns });

    std.debug.print(
        "  (pre-fix these three scaled with n = {d}; post-fix the first two are\n" ++
            "  interface_count-bounded and the third is bounded by what is actually queued)\n",
        .{n_entries},
    );
}
