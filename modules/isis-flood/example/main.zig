// SPDX-License-Identifier: MIT

//! What an IS-IS fabric integrator does with `isis-flood`: run a 4-node
//! point-to-point chain A—B—C—D, originate an LSP at A, and drain each
//! node's `isis-lsdb` SRM queue through its own `Scheduler.poll` to
//! actually flood it hop by hop — feeding the flooded bytes into the next
//! node's `Lsdb.insert` exactly as a real link would carry them. Along the
//! way this exercises every case the task cares about:
//!
//!   - **split horizon** — B and C must never flood A's LSP back the way it
//!     came (checked directly on `srmSet`, and again on the actual `poll`
//!     effects);
//!   - **a newer sequence number replacing an older one** — A re-originates
//!     at seq 2 and the whole chain re-converges;
//!   - **an older one being rejected** — a stale copy of A's seq-1 LSP is
//!     replayed at C after C already holds seq 2, and is refused;
//!   - **a corrupted LSP** — a received PDU with a mangled checksum is
//!     refused by NAMED error (ISO 10589 §7.3.14.2 e), not a blanket catch.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). Declared
//! deps: `isis`, `isis-lsdb`.

const std = @import("std");
const isis = @import("isis");
const lsdb = @import("isis-lsdb");
const flood = @import("isis-flood");

const sys_a: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };
const sys_c: [6]u8 = .{ 0, 0, 0, 0, 0, 0xC };
const sys_d: [6]u8 = .{ 0, 0, 0, 0, 0, 0xD };

fn idOf(sys: [6]u8) flood.LspId {
    return .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, 0 };
}

/// Build A's own LSP the way a conformant originator does: ISO 10589
/// §7.3.11 makes stamping the Checksum the generating IS's job, and every
/// receiving `insert` below enforces it (arrival_iface != null).
fn buildA(buf: []u8, seq: u32) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = 1000,
        .lsp_id = idOf(sys_a),
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finishStamped();
}

fn up(iface: u8) flood.InterfaceSet {
    var s = flood.InterfaceSet.initEmpty();
    s.set(iface);
    return s;
}
fn up2(a: u8, b: u8) flood.InterfaceSet {
    var s = up(a);
    s.set(b);
    return s;
}

/// Pull only the `.lsp` effects out of a `poll` result — this example drives
/// a single LSP end to end and does not process the PSNP/CSNP effects a real
/// deployment would also send (out of scope for what this file is testing).
fn onlyLsps(effects: []const flood.Effect, want_iface: ?u8) usize {
    var n: usize = 0;
    for (effects) |e| {
        if (e.kind != .lsp) continue;
        if (want_iface) |w| if (e.iface != w) continue;
        n += 1;
    }
    return n;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // Topology: A —(0)— B —(1)— C —(1)— D, a point-to-point chain.
    //   A: iface 0 -> B                 (interface_count = 1)
    //   B: iface 0 -> A, iface 1 -> C    (interface_count = 2)
    //   C: iface 0 -> B, iface 1 -> D    (interface_count = 2)
    //   D: iface 0 -> C                 (interface_count = 1)
    var a_db = lsdb.Lsdb.init(gpa, .{ .local_system_id = sys_a, .interface_count = 1, .capacity = 8 });
    defer a_db.deinit();
    var b_db = lsdb.Lsdb.init(gpa, .{ .local_system_id = sys_b, .interface_count = 2, .capacity = 8 });
    defer b_db.deinit();
    var c_db = lsdb.Lsdb.init(gpa, .{ .local_system_id = sys_c, .interface_count = 2, .capacity = 8 });
    defer c_db.deinit();
    var d_db = lsdb.Lsdb.init(gpa, .{ .local_system_id = sys_d, .interface_count = 1, .capacity = 8 });
    defer d_db.deinit();

    var a_sched = flood.Scheduler.init(gpa, .{ .local_system_id = sys_a, .min_lsp_transmission_interval = 5 });
    defer a_sched.deinit();
    var b_sched = flood.Scheduler.init(gpa, .{ .local_system_id = sys_b, .min_lsp_transmission_interval = 5 });
    defer b_sched.deinit();
    var c_sched = flood.Scheduler.init(gpa, .{ .local_system_id = sys_c, .min_lsp_transmission_interval = 5 });
    defer c_sched.deinit();

    var out: [16]flood.Effect = undefined;
    var scratch: [1024]u8 = undefined;
    const id_a = idOf(sys_a);

    // ── run 1: A originates seq=1, floods hop by hop to D ────────────────────
    var abuf: [128]u8 = undefined;
    const stale_seq1 = try gpa.dupe(u8, buildA(&abuf, 1)); // kept for the "older" replay below
    defer gpa.free(stale_seq1);
    _ = try a_db.insert(stale_seq1, null, 0); // A originates -> SRM on iface 0

    {
        const r = a_sched.poll(0, up(0), &a_db, &out, &scratch);
        std.debug.assert(onlyLsps(r.effects, 0) == 1);
        for (r.effects) |e| {
            if (e.kind != .lsp) continue;
            _ = try b_db.insert(e.bytes, 0, 0); // B receives on its iface 0 (arrival)
        }
    }
    // Split horizon at B: the LSP arrived on iface 0, so it must be queued to
    // flood on iface 1 (toward C) and NEVER back on iface 0 (toward A).
    std.debug.assert(b_db.srmSet(id_a).?.isSet(1));
    std.debug.assert(!b_db.srmSet(id_a).?.isSet(0));

    {
        const r = b_sched.poll(0, up2(0, 1), &b_db, &out, &scratch);
        std.debug.assert(onlyLsps(r.effects, 1) == 1); // only on the onward interface
        std.debug.assert(onlyLsps(r.effects, 0) == 0); // never back toward A
        for (r.effects) |e| {
            if (e.kind != .lsp or e.iface != 1) continue;
            _ = try c_db.insert(e.bytes, 0, 0); // C receives on its iface 0 (arrival, from B)
        }
    }
    // Split horizon at C too: must flood onward to D (iface 1), never back to B.
    std.debug.assert(c_db.srmSet(id_a).?.isSet(1));
    std.debug.assert(!c_db.srmSet(id_a).?.isSet(0));

    {
        const r = c_sched.poll(0, up2(0, 1), &c_db, &out, &scratch);
        std.debug.assert(onlyLsps(r.effects, 1) == 1);
        for (r.effects) |e| {
            if (e.kind != .lsp or e.iface != 1) continue;
            _ = try d_db.insert(e.bytes, 0, 0); // D receives on its iface 0 (arrival, from C)
        }
    }
    std.debug.assert(d_db.get(id_a, 0) != null);
    std.debug.assert(d_db.get(id_a, 0).?.sequence_number == 1);
    std.debug.print("run 1: A's seq=1 LSP propagated A->B->C->D, split horizon held at every hop\n", .{});

    // ── newer sequence number replacing an older one ─────────────────────────
    // A re-originates at seq=2 (a genuinely newer LSP, not a retransmit) and
    // the whole chain re-converges on it. Poll well past the retransmit
    // interval so this is unambiguously the new-content flood, not a stale
    // retransmit of seq=1.
    const r2 = try a_db.insert(buildA(&abuf, 2), null, 20);
    std.debug.assert(r2.ordering == .newer and r2.stored);

    {
        const r = a_sched.poll(20, up(0), &a_db, &out, &scratch);
        for (r.effects) |e| {
            if (e.kind != .lsp) continue;
            const ins = try b_db.insert(e.bytes, 0, 20);
            std.debug.assert(ins.ordering == .newer and ins.stored);
        }
    }
    {
        const r = b_sched.poll(20, up2(0, 1), &b_db, &out, &scratch);
        for (r.effects) |e| {
            if (e.kind != .lsp or e.iface != 1) continue;
            const ins = try c_db.insert(e.bytes, 0, 20);
            std.debug.assert(ins.ordering == .newer and ins.stored);
        }
    }
    {
        const r = c_sched.poll(20, up2(0, 1), &c_db, &out, &scratch);
        for (r.effects) |e| {
            if (e.kind != .lsp or e.iface != 1) continue;
            const ins = try d_db.insert(e.bytes, 0, 20);
            std.debug.assert(ins.ordering == .newer and ins.stored);
        }
    }
    std.debug.assert(d_db.get(id_a, 20).?.sequence_number == 2);
    std.debug.print("run 2 (topology unchanged, LSP updated): seq=2 propagated end to end, superseding seq=1\n", .{});

    // ── an older sequence number is rejected ──────────────────────────────────
    // A stale/late neighbour replays A's original seq=1 bytes directly at C,
    // which already holds seq=2. Named-error-free path (this is a normal,
    // well-formed PDU — just stale), so the signal is the `InsertResult`, not
    // an error: `.older`, not stored, and per ISO 10589 §7.3.15 the receiver
    // re-floods ITS newer copy back out the arrival circuit to correct the
    // stale sender (this is the one case where SRM legitimately gets set on
    // the arrival interface — it is a correction, not a split-horizon flood).
    {
        const before = c_db.get(id_a, 20).?.sequence_number;
        const older = try c_db.insert(stale_seq1, 0, 25);
        std.debug.assert(older.ordering == .older);
        std.debug.assert(!older.stored);
        std.debug.assert(c_db.get(id_a, 25).?.sequence_number == before); // unchanged
        std.debug.assert(c_db.srmSet(id_a).?.isSet(0)); // correct the stale sender back
        std.debug.print("older replay of seq=1 at C (holding seq=2): rejected (ordering=.older, stored=false)\n", .{});
    }

    // ── a corrupted LSP is refused by NAMED error, not a blanket catch ───────
    // ISO 10589 §7.3.14.2 e): a RECEIVED LSP (arrival_iface != null) with a
    // wrong Fletcher checksum is discarded before any comparison. Take a
    // validly-stamped LSP with a real TLV body (so a payload byte exists to
    // flip without touching the fixed header) and corrupt one payload byte.
    {
        var buf: [256]u8 = undefined;
        var b = try isis.pdu.LspBuilder.init(&buf, .{
            .remaining_lifetime = 1000,
            .lsp_id = idOf(sys_a),
            .sequence_number = 3,
            .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
        });
        const nbr: [7]u8 = .{ sys_b[0], sys_b[1], sys_b[2], sys_b[3], sys_b[4], sys_b[5], 0 };
        try isis.tlvs.addExtendedIsReach(&b.tlvs, nbr, 10, &.{});
        const good = b.finishStamped();
        var mangled = try gpa.dupe(u8, good);
        defer gpa.free(mangled);
        // NOT `^= 0xFF`: this checksum is a mod-255 Fletcher (ISO 8473 Annex
        // B), under which byte values 0x00 and 0xFF are congruent (0 and 255
        // are the same residue mod 255) — XOR-0xFF against a zero byte is
        // exactly the one mutation this checksum cannot see. A wrapping
        // increment has no such blind spot.
        mangled[mangled.len - 3] +%= 1;

        const before = d_db.count();
        if (d_db.insert(mangled, 0, 30)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.CorruptedLsp => std.debug.print("corrupted checksum at D: CorruptedLsp (expected), store unchanged\n", .{}),
            else => return err,
        }
        std.debug.assert(d_db.count() == before); // rejected cleanly, nothing stored
    }

    // ── a failure path that allocates and returns early, by NAMED error ─────
    // `Lsdb.insert`'s error checks (DatabaseFull, SequenceExhausted,
    // CorruptedLsp) all return BEFORE any allocation on this module's own
    // documented contract ("the store is left unchanged"). The one place
    // this module genuinely allocates-then-can-fail is the hash-map growth
    // inside `insert` itself (`std.mem.Allocator.Error`, part of
    // `InsertError`) — reachable under real allocator exhaustion. Drive it
    // directly with a `FailingAllocator` on a fresh store.
    {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
        var fdb = lsdb.Lsdb.init(failing.allocator(), .{ .local_system_id = sys_a, .interface_count = 1, .capacity = 8 });
        defer fdb.deinit();
        var fbuf: [128]u8 = undefined;
        if (fdb.insert(buildA(&fbuf, 1), null, 0)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.OutOfMemory => std.debug.print("insert under a FailingAllocator: OutOfMemory (expected), store left empty\n", .{}),
            else => return err,
        }
        std.debug.assert(fdb.count() == 0); // nothing partially stored
    }
}
