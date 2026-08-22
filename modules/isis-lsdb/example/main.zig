// SPDX-License-Identifier: MIT

//! What an IS-IS flooding layer does with `isis-lsdb`: hold a link-state
//! database, originate one LSP, receive a corrupted one from a circuit (and
//! reject it by name), then reconcile against a neighbour's CSNP summary and
//! flood the delta — the update process in ISO/IEC 10589 §7.3, minus the
//! socket I/O this module deliberately leaves to the caller.

const std = @import("std");
const isis = @import("isis");
const lsdb = @import("isis-lsdb");

const sys_local: [6]u8 = .{ 0, 0, 0, 0, 0, 0x01 };
const sys_peer: [6]u8 = .{ 0, 0, 0, 0, 0, 0x02 };

/// Builds and stamps one LSP the way a real originator would: fixed header,
/// life/sequence, then the ISO Fletcher checksum `insert` requires on receipt.
fn buildLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finishStamped();
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var db = lsdb.Lsdb.init(gpa, .{ .local_system_id = sys_local, .interface_count = 2, .capacity = 16 });
    defer db.deinit();

    // Originate our own LSP (local origination is checksum-exempt).
    var own_buf: [128]u8 = undefined;
    const own = buildLsp(&own_buf, sys_local, 0, 1, 1000);
    const r0 = try db.insert(own, null, 0);
    std.debug.print("originated: stored={} ordering={s}\n", .{ r0.stored, @tagName(r0.ordering) });

    // A circuit hands us bytes with a stamped checksum, then we flip one
    // payload byte after the fact — a corrupted LSP arriving over the wire.
    // The receive-side self-defence (§7.3.14.2 e) must reject it by name
    // rather than silently discard or, worse, store it.
    var bad_buf: [128]u8 = undefined;
    const bad_len = buildLsp(&bad_buf, sys_peer, 0, 1, 1000).len;
    bad_buf[bad_len - 3] ^= 0xFF; // corrupt a payload byte after stamping
    const bad = bad_buf[0..bad_len];
    if (db.insert(bad, 0, 0)) |_| {
        std.debug.print("unexpected: corrupted LSP accepted\n", .{});
    } else |err| switch (err) {
        error.CorruptedLsp => std.debug.print("insert(corrupted): CorruptedLsp (expected)\n", .{}),
        else => return err,
    }
    std.debug.assert(db.count() == 1); // the reject left the store unchanged

    // The neighbour's CSNP summarises ITS database: one LSP we don't have.
    var peer = lsdb.Lsdb.init(gpa, .{ .local_system_id = sys_peer, .interface_count = 2, .capacity = 16 });
    defer peer.deinit();
    var peer_buf: [128]u8 = undefined;
    _ = try peer.insert(buildLsp(&peer_buf, sys_peer, 0, 1, 1000), null, 0);

    var summary: [8]isis.tlvs.LspEntry = undefined;
    const n = peer.summarise(&summary, @splat(0), @splat(0xFF), 0);

    var csnp_buf: [256]u8 = undefined;
    var cb = isis.pdu.CsnpBuilder.init(&csnp_buf, .{
        .source_id = .{ sys_peer[0], sys_peer[1], sys_peer[2], sys_peer[3], sys_peer[4], sys_peer[5], 0 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xFF),
    }) catch unreachable;
    try isis.tlvs.addLspEntries(&cb.tlvs, summary[0..n]);
    const csnp = try isis.Csnp.decode(cb.finish());

    // Reconciling the CSNP on circuit 1: our LSP is missing from the peer's
    // summary (SRM: flood it out) and the peer's LSP is missing from ours
    // (SSN: request it).
    db.reconcileCsnp(csnp, 1, 0);

    const local_id: lsdb.LspId = .{ sys_local[0], sys_local[1], sys_local[2], sys_local[3], sys_local[4], sys_local[5], 0, 0 };
    const peer_id: lsdb.LspId = .{ sys_peer[0], sys_peer[1], sys_peer[2], sys_peer[3], sys_peer[4], sys_peer[5], 0, 0 };
    std.debug.print(
        "after reconcile: SRM(local LSP, circuit 1)={} SSN(peer LSP, circuit 1)={}\n",
        .{ db.srmSet(local_id).?.isSet(1), db.ssnSet(peer_id).?.isSet(1) },
    );

    // Flood the SRM-queued LSP(s) out circuit 1 into the peer's database —
    // the actual wire bytes an outer transmit loop would send.
    var it = db.srmIterator(1);
    var flooded: usize = 0;
    while (it.next()) |item| {
        _ = try peer.insert(item.bytes, 0, 2);
        flooded += 1;
    }
    std.debug.print("flooded {d} LSP(s) into the peer; peer now holds our LSP: {}\n", .{ flooded, peer.get(local_id, 2) != null });
}
