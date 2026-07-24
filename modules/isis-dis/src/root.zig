// SPDX-License-Identifier: MIT

//! isis-dis — IS-IS LAN Designated-IS (DIS) election (ISO/IEC 10589 §8.4.5): a
//! pure, time-injected election for ONE LAN circuit at one level. From the set of
//! routers seen on the LAN (each with its priority + SNPA/MAC, as the caller
//! derives from received LAN Hellos + adjacency state) it elects the DIS — the
//! **highest priority**, ties broken by the **highest SNPA**, with **immediate
//! preemption and no hold-down** (unlike OSPF's DR) — reports whether THIS system
//! is the DIS, and derives the pseudonode LSP-ID the DIS originates. No threads,
//! no owned timers, no sockets, no allocation: the caller supplies the neighbour
//! view + `now` and acts on the emitted DIS-change effect (`became_dis` /
//! `resigned_dis` for the local system).
//!
//! ## Layers
//! - `election` — the pure `elect(local, neighbours) -> Result` function, the
//!   `Candidate`/`Result` types, and the pseudonode LSP-ID derivation. Order-
//!   independent; the whole election rule lives here.
//! - `fsm` — the `Election` wrapper that stores the current DIS, `recompute`s over
//!   the current candidate set, and emits a `DisChange` when the winner flips.
//!
//! ## Pairing with the isis stack
//! Builds on the sibling `isis` codec (the LAN IIH `lan_id` this election derives
//! is exactly `isis.LanHello.lan_id`; the pseudonode LSP-ID matches
//! `isis.Lsp.lsp_id`). It is the LAN counterpart to the P2P `isis-adj` FSM and
//! feeds the pseudonode-LSP origination an `isis-lsdb`/`isis-flood` consumer would
//! own. This module does the *election only* — not the pseudonode LSP content, not
//! LAN adjacency formation, not multi-level DIS (see SPEC.md).
//!
//! Provenance: clean-room from ISO/IEC 10589 §8.4.5; no third-party IS-IS
//! implementation consulted. See /NOTICE (no entry required — public spec).

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §8.4.5 LAN DIS election (priority + SNPA, preemptive)",
    .deps = .{"isis"},
};

pub const election = @import("election.zig");
pub const fsm = @import("fsm.zig");

// ── the most-used surface, re-exported ───────────────────────────────────────
pub const SystemId = election.SystemId;
pub const Snpa = election.Snpa;
pub const Candidate = election.Candidate;
pub const Result = election.Result;
pub const elect = election.elect;

pub const Time = fsm.Time;
pub const Election = fsm.Election;
pub const Effect = fsm.Effect;
pub const DisChange = fsm.DisChange;

// ── integration tests: the election + FSM against the isis LAN Hello shape ───

const testing = std.testing;
const isis = @import("isis");

fn snpa(last: u8) Snpa {
    return .{ 0x00, 0x00, 0x00, 0x00, 0x00, last };
}

// The derived `lan_id` and pseudonode LSP-ID must slot straight into the sibling
// `isis` LAN Hello / LSP shapes: the LAN IIH advertises `lan_id` (system-id ‖
// pseudonode-id), and the pseudonode LSP's id is that ‖ LSP-number. This proves
// the widths line up end-to-end with the codec, not just in isolation.
test "derived lan_id round-trips through an isis LAN Hello; LSP-ID matches isis.Lsp" {
    const dis: Candidate = .{ .system_id = .{ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 }, .priority = 64, .snpa = snpa(0x02), .pseudonode_id = 3 };
    const r = elect(dis, &.{});
    try testing.expect(r.is_local_dis);

    // Feed the elected lan_id into a real isis LAN IIH and read it back.
    var buf: [128]u8 = undefined;
    var b = try isis.pdu.LanHelloBuilder.init(&buf, .{
        .source_id = r.dis_system_id,
        .holding_time = 30,
        .priority = 64,
        .lan_id = r.lan_id,
    });
    const wire = b.finish();
    const p = try isis.LanHello.decode(wire);
    try testing.expectEqual(r.lan_id, p.lan_id);
    try testing.expectEqual(@as(u8, 3), p.lan_id[6]); // the pseudonode id

    // The pseudonode LSP-ID is exactly the 8-octet shape isis.Lsp.lsp_id expects.
    const lsp_id = r.pseudonodeLspId();
    var lbuf: [128]u8 = undefined;
    var lb = try isis.pdu.LspBuilder.init(&lbuf, .{
        .remaining_lifetime = 1200,
        .lsp_id = lsp_id,
        .sequence_number = 1,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    const lwire = lb.finish();
    const lsp = try isis.Lsp.decode(lwire);
    try testing.expectEqual(lsp_id, lsp.lsp_id);
    try testing.expectEqual(@as(u8, 3), lsp.lsp_id[6]); // pseudonode id nonzero ⇒ pseudonode LSP
    try testing.expectEqual(@as(u8, 0), lsp.lsp_id[7]); // LSP number 0
}

// A small LAN driven through the FSM: local + two neighbours, then the DIS
// preempted by a late higher-priority arrival and restored on its departure —
// bounded by the neighbour count, no unbounded loops.
test "small LAN: DIS elected, preempted, restored, with correct effects" {
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0xA }, .priority = 64, .snpa = snpa(0xAA), .pseudonode_id = 1 };
    const n1: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0xB }, .priority = 64, .snpa = snpa(0x10) };
    const n2: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0xC }, .priority = 64, .snpa = snpa(0x20) };
    const king: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0xD }, .priority = 127, .snpa = snpa(0x01) };

    var e = Election.init(local);
    // Local (SNPA 0xAA) beats both equal-priority neighbours on SNPA → local DIS.
    const s0 = e.recompute(&.{ n1, n2 }, 1);
    try testing.expect(s0.result.is_local_dis);
    try testing.expect(s0.change.?.became_dis);

    // The priority-127 king arrives → immediate preemption, local resigns.
    const s1 = e.recompute(&.{ n1, n2, king }, 2);
    try testing.expect(!s1.result.is_local_dis);
    try testing.expectEqual(king.system_id, s1.result.dis_system_id);
    try testing.expect(s1.change.?.resigned_dis);

    // The king leaves → local is DIS again, no backoff.
    const s2 = e.recompute(&.{ n1, n2 }, 3);
    try testing.expect(s2.result.is_local_dis);
    try testing.expect(s2.change.?.became_dis);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("election.zig");
    _ = @import("fsm.zig");
}
