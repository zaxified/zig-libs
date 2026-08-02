// SPDX-License-Identifier: MIT

//! External anchor: Wireshark 4.6.4 (sharkd, via `scripts/dissect.py`).
//!
//! `isis-dis`'s own `ANCHOR-TASKS.tsv` row before this file read `SELF`,
//! justified as "lan_id/LSP-ID checked via sibling isis only" — i.e. the claim
//! that because the bytes this module derives pass through the already-
//! anchored `isis` codec, the codec's anchor covers this module too. Per the
//! audit brief a sibling's anchor does not transfer: what needs an outside
//! oracle is the LAN-Hello/DIS content *this* module produces — the derived
//! `lan_id` (DIS system-id ‖ pseudonode byte), the priority it carries onto the
//! wire, the L1/L2 PDU type selection, and the pseudonode LSP-ID — not the
//! generic PDU framing (length-indicator, PDU length, common header), which
//! genuinely is the sibling `isis` codec's own already-anchored surface (same
//! reasoning `isis-adj`'s row uses for the P2P Hello framing it doesn't
//! re-anchor).
//!
//! Every vector below is produced by calling **this module's own `elect()`**
//! to get a real `Result`, then feeding its `lan_id` / `pseudonodeLspId()`
//! straight into the sibling `isis` codec's real `LanHelloBuilder`/
//! `LspBuilder` (`isis-dis` has no wire-framing code of its own — see
//! `root.zig`'s pre-existing integration test, which does the same wiring
//! without a dissector) — not a hand-derived expected value. The resulting
//! wire bytes were then fed through Wireshark's real IS-IS dissector.
//!
//! What this closes, and what it deliberately does not: the DIS election
//! *algorithm* (highest-priority, tie-broken by highest-SNPA) is a pure
//! in-memory computation with no wire representation — a dissector cannot
//! grade it, and nothing below claims to. Only the election's wire-visible
//! *inputs and outputs* — `lan_id`, `priority`, the L1/L2 Hello type code, and
//! the pseudonode LSP-ID — are anchored here.
//!
//! The `dissect.py` runs happened once, interactively, while writing this
//! file. The frozen byte arrays plus the quoted Wireshark output below are what
//! makes the anchor re-checkable without re-running the tool — the test suite
//! itself never invokes `dissect.py`/`sharkd`/`text2pcap` (no new build
//! dependency).

const std = @import("std");
const isis = @import("isis");
const election = @import("election.zig");
const elect = election.elect;
const Candidate = election.Candidate;
const testing = std.testing;

fn snpa(last: u8) election.Snpa {
    return .{ 0x00, 0x00, 0x00, 0x00, 0x00, last };
}

// ── Golden 1: L1 LAN Hello — local is DIS, priority at the 127 boundary ──────
//
// `local` is the sole candidate (empty neighbour set) so `elect` makes it the
// DIS unconditionally (SPEC §3.2: a priority-0 *or* priority-127 router still
// wins as the sole candidate) — chosen at the top of the 7-bit priority range
// to check the reserved high bit stays clear on the wire.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 0f 01 00 03 03 00 00
//   00 00 00 11 00 1e 00 1b 7f 00 00 00 00 00 11 09'
//
// Wireshark printed (verbatim, trimmed to the load-bearing lines):
//   isis.type == 15 = ...0 1111 = PDU Type: L1 HELLO (15)
//   isis.hello.source_id == 0000.0000.0011 = SystemID {Sender of PDU}
//   isis.hello.holding_timer == 30 = Holding timer: 30
//   isis.hello.pdu_length == 27 = PDU length: 27
//   isis.hello.priority == 127 = .111 1111 = Priority: 127
//   isis.hello.reserved == 0 = 0... .... = Reserved: 0
//   isis.hello.lan_id == 0000.0000.0011.09 = SystemID {Designated IS}: 0000.0000.0011.09
// (No expert info of any kind — checked via --json — on this or either other
// vector in this file.)
const golden_lan_hello_local_dis = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x0f, 0x01, 0x00, 0x03,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00,
    0x1e, 0x00, 0x1b, 0x7f, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x11, 0x09,
};

test "golden L1 LAN Hello (Wireshark-anchored): elect()'s Result drives isis's real LanHelloBuilder, local DIS, priority 127" {
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0x11 }, .priority = 127, .snpa = snpa(0x11), .pseudonode_id = 9 };
    const r = elect(local, &.{});
    try testing.expect(r.is_local_dis);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0x11, 9 }, &r.lan_id);

    var buf: [64]u8 = undefined;
    var b = try isis.pdu.LanHelloBuilder.init(&buf, .{
        .is_l2 = false,
        .source_id = r.dis_system_id,
        .holding_time = 30,
        .priority = local.priority,
        .lan_id = r.lan_id,
    });
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_lan_hello_local_dis, wire);

    // The decoder agrees with what Wireshark printed (byte-shape cross-check;
    // the actual anchor is the frozen Wireshark output above, not this).
    const p = try isis.LanHello.decode(wire);
    try testing.expectEqual(@as(u7, 127), p.priority);
    try testing.expectEqual([7]u8{ 0, 0, 0, 0, 0, 0x11, 9 }, p.lan_id);
}

// ── Golden 2: L2 LAN Hello — DIS is a remote neighbour, local priority 0 ─────
//
// `local` (priority 0, "never want to be DIS") loses to a positive-priority
// neighbour (SPEC §3.2); the Hello is sent BY `local` (source_id = local's own
// id) but ADVERTISES the winning neighbour's id in `lan_id`, per SPEC §5.1
// ("When a different router is DIS the local system is not the origin;
// `lan_id` then exposes that DIS's system-id ‖ observed pseudonode-id"). Also
// exercises the L2 PDU type code (16) and the 0 end of the priority range.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 10 01 00 03 02 00 00
//   00 00 00 22 00 1e 00 1b 00 00 00 00 00 00 33 07'
//
// Wireshark printed:
//   isis.type == 16 = ...1 0000 = PDU Type: L2 HELLO (16)
//   isis.hello.circuit_type == 0x02 = .... ..10 = Circuit type: Level 2 only (0x2)
//   isis.hello.source_id == 0000.0000.0022 = SystemID {Sender of PDU}
//   isis.hello.priority == 0 = .000 0000 = Priority: 0
//   isis.hello.lan_id == 0000.0000.0033.07 = SystemID {Designated IS}: 0000.0000.0033.07
const golden_lan_hello_remote_dis = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x10, 0x01, 0x00, 0x03,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
    0x1e, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x33, 0x07,
};

test "golden L2 LAN Hello (Wireshark-anchored): elect()'s Result drives isis's real LanHelloBuilder, remote DIS, priority 0" {
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0x22 }, .priority = 0, .snpa = snpa(0x22) };
    const nb: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0x33 }, .priority = 50, .snpa = snpa(0x33), .pseudonode_id = 7 };
    const r = elect(local, &.{nb});
    try testing.expect(!r.is_local_dis);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0x33, 7 }, &r.lan_id);

    var buf: [64]u8 = undefined;
    var b = try isis.pdu.LanHelloBuilder.init(&buf, .{
        .is_l2 = true,
        .circuit_type = .level2,
        .source_id = local.system_id,
        .holding_time = 30,
        .priority = local.priority,
        .lan_id = r.lan_id,
    });
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_lan_hello_remote_dis, wire);

    const p = try isis.LanHello.decode(wire);
    try testing.expectEqual(@as(u7, 0), p.priority);
    try testing.expectEqual([7]u8{ 0, 0, 0, 0, 0, 0x33, 7 }, p.lan_id);
}

// ── Golden 3: pseudonode LSP-ID, driven through isis's real LSP builder ──────
//
// The DIS from Golden 1 (system-id ..11, pseudonode 9) originates the
// pseudonode LSP; `Result.pseudonodeLspId()` supplies the 8-octet id.
//
// Command:
//   scripts/dissect.py --frame llc --fields '83 1b 01 06 12 01 00 03 00 1b 04
//   b0 00 00 00 00 00 11 09 00 00 00 00 01 00 00 01'
//
// Wireshark printed:
//   isis.type == 18 = ...1 0010 = PDU Type: L1 LSP (18)
//   isis.lsp.pdu_length == 27 = PDU length: 27
//   isis.lsp.remaining_life == 1200 = Remaining lifetime: 1200
//   isis.lsp.lsp_id == 0000.0000.0011.09-00 = LSP-ID: 0000.0000.0011.09-00
//   isis.lsp.sequence_number == 0x00000001 = Sequence number: 0x00000001
//   isis.lsp.is_type == 1 = .... ..01 = Type of Intermediate System: Level 1 (1)
// Wireshark's own LSP-ID split (`....0011.09-00`) confirms the byte order this
// module derives: system-id (6) ‖ pseudonode (1, non-zero ⇒ pseudonode LSP) ‖
// LSP-number (1, here 0) — exactly `pseudonodeLspId()`'s doc comment.
const golden_pseudonode_lsp = [_]u8{
    0x83, 0x1b, 0x01, 0x06, 0x12, 0x01, 0x00, 0x03,
    0x00, 0x1b, 0x04, 0xb0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x11, 0x09, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01,
};

test "golden pseudonode LSP-ID (Wireshark-anchored): pseudonodeLspId() drives isis's real LspBuilder" {
    const local: Candidate = .{ .system_id = .{ 0, 0, 0, 0, 0, 0x11 }, .priority = 127, .snpa = snpa(0x11), .pseudonode_id = 9 };
    const r = elect(local, &.{});
    const lsp_id = r.pseudonodeLspId();
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0x11, 9, 0 }, &lsp_id);

    var buf: [64]u8 = undefined;
    var b = try isis.pdu.LspBuilder.init(&buf, .{
        .remaining_lifetime = 1200,
        .lsp_id = lsp_id,
        .sequence_number = 1,
        .checksum = 0,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    });
    const wire = b.finish();
    try testing.expectEqualSlices(u8, &golden_pseudonode_lsp, wire);

    const p = try isis.Lsp.decode(wire);
    try testing.expectEqual(lsp_id, p.lsp_id);
    try testing.expectEqual(@as(u8, 9), p.lsp_id[6]); // pseudonode byte, non-zero
    try testing.expectEqual(@as(u8, 0), p.lsp_id[7]); // LSP number 0
}
