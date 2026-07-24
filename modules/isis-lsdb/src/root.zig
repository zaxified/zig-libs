// SPDX-License-Identifier: MIT
//! isis-lsdb — the IS-IS link-state database for one level (ISO/IEC 10589 §7.3):
//! store LSPs keyed by LSP-ID, apply the §7.3.16.1 newer-LSP comparison
//! (sequence-number → zero-lifetime-purge-wins → checksum tie-break), age
//! Remaining Lifetime on a time-injected `tick` and purge at `MaxAge`/
//! `ZeroAgeLifetime`, and maintain the per-interface SRM (flood) / SSN
//! (acknowledge) flag sets a flooding layer consumes — plus the CSNP/PSNP
//! database-synchronisation reconcile. Pure and single-owner: no threads, no
//! owned timers, no sockets; the caller supplies `now` and drives all I/O.
//! Builds on the sibling `isis` codec (the `Lsp` PDU + the LSP-Entries #9 TLV);
//! the flooding transmit loop and SPF are later consumers.
//!
//! ## Layers
//! - `compare` — the ISO §7.3.16.1 newer-LSP comparison (the correctness core),
//!   pure and std-only, with a deliberately-broken variant for the positive
//!   control.
//! - `store` — the `Lsdb`: the LSP-ID-keyed store, the update process
//!   (`insert` → comparison → SRM/SSN flags), time-injected aging + purge, the
//!   flooding-flag query surface, and the CSNP/PSNP reconcile.
//!
//! ## Time-injection contract
//! Identical to the sibling `isis-adj` FSM: the store never reads a clock. Every
//! entry point that cares about time takes a caller-supplied monotonic `now:
//! Time` (abstract ticks in the caller's own unit); a stored LSP's Remaining
//! Lifetime is *derived* from the `now` it was set at, so aging is a comparison,
//! never an owned countdown. Given the same `(ops, now)` stream the database and
//! its flag state are fully deterministic.
//!
//! ## Capacity / DoS bound
//! The store is bounded by `Config.capacity`: a new distinct LSP-ID is admitted
//! only while `count() < capacity`, else `insert` returns `error.DatabaseFull`
//! (unchanged). A flood of distinct LSP-IDs — or of SNP entries requesting LSPs
//! we lack — cannot grow the database without limit. See `SPEC.md`.
//!
//! Provenance: clean-room from ISO/IEC 10589 §7.3; the §7.3.16.1 comparison was
//! cross-checked against FRRouting `isis_lsp.c:lsp_compare` for the (oriented)
//! purge/checksum tie-break. No third-party source ported. See /NOTICE (no entry
//! required — public specs).

const std = @import("std");
const isis = @import("isis");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §7.3 link-state database (update process, SRM/SSN)",
    .deps = .{"isis"},
};

pub const compare = @import("compare.zig");
pub const store = @import("store.zig");

// ── the most-used surface, re-exported ───────────────────────────────────────
pub const Lsdb = store.Lsdb;
pub const Config = store.Config;
pub const Time = store.Time;
pub const LspId = store.LspId;
pub const InterfaceSet = store.InterfaceSet;
pub const InsertResult = store.InsertResult;
pub const InsertError = store.InsertError;
pub const AgeReport = store.AgeReport;
pub const EntryView = store.EntryView;
pub const Ordering = compare.Ordering;
pub const LspVersion = compare.LspVersion;
pub const compareVersions = compare.compare;
pub const max_interfaces = store.max_interfaces;

// ── integration test: two databases synchronise via CSNP + flooding ──────────

const testing = std.testing;

const sys_a: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };

fn buildLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16, csum: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num },
        .sequence_number = seq,
        .checksum = csum,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finish();
}

// The end-to-end proof: B holds an LSP that A lacks. A learns of it from B's
// CSNP (→ SSN request), and A floods its own LSP that B's CSNP omitted. Then the
// actual LSP bytes A holds for flooding are fed into B via `insert`, and B
// stores them — the two databases converge, all through the `isis` wire codec.
test "two databases reconcile a CSNP and flood the delta into each other" {
    var a = Lsdb.init(testing.allocator, .{ .local_system_id = sys_a, .interface_count = 2, .capacity = 16 });
    defer a.deinit();
    var b = Lsdb.init(testing.allocator, .{ .local_system_id = sys_b, .interface_count = 2, .capacity = 16 });
    defer b.deinit();

    var buf: [128]u8 = undefined;

    // A originates its own LSP (floods out every circuit).
    _ = try a.insert(buildLsp(&buf, sys_a, 0, 1, 1000, 0xAAAA), null, 0);
    // B originates its own LSP.
    _ = try b.insert(buildLsp(&buf, sys_b, 0, 1, 1000, 0xBBBB), null, 0);

    // B sends A a CSNP summarising B's whole DB (just B's own LSP). A holds A's
    // LSP but not B's.
    var cbuf: [256]u8 = undefined;
    var out: [8]isis.tlvs.LspEntry = undefined;
    const n = b.summarise(&out, @splat(0), @splat(0xFF), 0);
    var cb = isis.pdu.CsnpBuilder.init(&cbuf, .{
        .source_id = .{ sys_b[0], sys_b[1], sys_b[2], sys_b[3], sys_b[4], sys_b[5], 0 },
        .start_lsp_id = @splat(0),
        .end_lsp_id = @splat(0xFF),
    }) catch unreachable;
    try isis.tlvs.addLspEntries(&cb.tlvs, out[0..n]);
    const cwire = cb.finish();

    const csnp = try isis.Csnp.decode(cwire);
    a.reconcileCsnp(csnp, 1, 1);

    // A now wants B's LSP (SSN request placeholder) and will flood its own LSP
    // (SRM on the CSNP circuit, since B's CSNP omitted A's LSP).
    const b_id: LspId = .{ sys_b[0], sys_b[1], sys_b[2], sys_b[3], sys_b[4], sys_b[5], 0, 0 };
    const a_id: LspId = .{ sys_a[0], sys_a[1], sys_a[2], sys_a[3], sys_a[4], sys_a[5], 0, 0 };
    try testing.expect(a.get(b_id, 1).?.is_request);
    try testing.expect(a.ssnSet(b_id).?.isSet(1));
    try testing.expect(a.srmSet(a_id).?.isSet(1));

    // A floods its SRM-queued LSP(s) out circuit 1 → feed them into B.
    var it = a.srmIterator(1);
    while (it.next()) |item| {
        _ = try b.insert(item.bytes, 0, 2);
    }
    // B now holds A's LSP → the databases have converged on A's LSP.
    try testing.expect(b.get(a_id, 2) != null);
    try testing.expectEqual(@as(u32, 1), b.get(a_id, 2).?.sequence_number);
}

// ── fuzz: hostile LSP bytes must never panic and never corrupt the store ──────

test "fuzz: insert on hostile bytes never panics; a rejected LSP leaves the store unchanged" {
    try std.testing.fuzz({}, fuzzInsert, .{});
}

fn fuzzInsert(_: void, smith: *std.testing.Smith) !void {
    var db = Lsdb.init(testing.allocator, .{ .local_system_id = sys_a, .interface_count = 2, .capacity = 32 });
    defer db.deinit();

    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, @intCast(buf.len));
    const input = buf[0..len];

    // Bias toward a valid-looking LSP header so deeper paths are exercised.
    if (len >= 27 and smith.value(bool)) {
        buf[0] = 0x83; // discriminator
        buf[1] = 27; // length indicator (LSP fixed header)
        buf[2] = 1; // version
        buf[3] = 0; // id length 0 => 6
        buf[4] = 18; // l1_lsp
        buf[5] = 1; // version
    }

    const before = db.count();
    if (db.insert(input, 0, 1)) |_| {
        // Accepted, ignored, or refused — all leave a coherent store.
    } else |_| {
        // A decode error (or DatabaseFull) must be inert w.r.t. membership.
        try testing.expectEqual(before, db.count());
    }
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("compare.zig");
    _ = @import("store.zig");
}
