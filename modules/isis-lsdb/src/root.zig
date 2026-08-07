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
//! we lack — cannot grow the database without limit. Request placeholders (born
//! from *unauthenticated* SNP bytes) additionally get their own sub-budget
//! (`Config.request_capacity`) and their own timeout (`Config.request_timeout`),
//! so a hostile SNP can neither wedge nor starve the database. See `SPEC.md`.
//!
//! ## Receive-side self-defence (ISO/IEC 10589 §7.3.16.1)
//! IS-IS here is unauthenticated (auth is deferred, `SPEC.md` §8), so the update
//! process must defend itself against an on-link peer: a copy of **our own** LSP
//! received from a circuit is never accepted (the owner is told to re-originate
//! at `InsertResult.self_challenge + 1`), a local origination at
//! `max_sequence_number` is `error.SequenceExhausted` rather than a permanent
//! self-lockout, and a **received** LSP whose ISO Fletcher checksum does not
//! check out is discarded with `error.CorruptedLsp` before any comparison
//! (§7.3.14.2 e), the precondition §7.3.16.1(d)'s checksum tie-break assumes —
//! see `compare.zig`). Purges and locally originated LSPs are exempt, for the
//! reasons spelled out at `Lsdb.insert`. What remains missing is
//! **authentication** (RFC 5304/5310, `SPEC.md` §8): the checksum is unkeyed, so
//! it stops corruption and accidents, not a determined on-link forger.
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
pub const max_sequence_number = store.max_sequence_number;

// ── integration test: two databases synchronise via CSNP + flooding ──────────

const testing = std.testing;

const sys_a: [6]u8 = .{ 0, 0, 0, 0, 0, 0xA };
const sys_b: [6]u8 = .{ 0, 0, 0, 0, 0, 0xB };

/// Stamps the ISO 10589 §7.3.11 checksum: the LSP A floods is *received* by B in
/// this test, and `insert`'s §7.3.14.2 gate discards an LSP that does not carry
/// one (the fixture previously used a `0xAAAA` placeholder, which is not a valid
/// checksum for these bytes and would now be refused — correctly).
fn buildLsp(buf: []u8, sys: [6]u8, lsp_num: u8, seq: u32, life: u16) []const u8 {
    var b = isis.pdu.LspBuilder.init(buf, .{
        .remaining_lifetime = life,
        .lsp_id = .{ sys[0], sys[1], sys[2], sys[3], sys[4], sys[5], 0, lsp_num },
        .sequence_number = seq,
        .flags = .{ .partition_repair = false, .attached = 0, .overload = false, .is_type = 1 },
    }) catch unreachable;
    return b.finishStamped();
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
    _ = try a.insert(buildLsp(&buf, sys_a, 0, 1, 1000), null, 0);
    // B originates its own LSP.
    _ = try b.insert(buildLsp(&buf, sys_b, 0, 1, 1000), null, 0);

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
        // ISO 10589 §7.3.14.2: a received LSP with a wrong Fletcher checksum is
        // discarded before the store is touched, so random bytes would now
        // almost never get past `insert`'s front door. Stamp a correct checksum
        // on some of them to keep the deep store path (compare → fill → flags)
        // as reachable as it was before that gate existed, while the unstamped
        // half keeps fuzzing the discard path itself.
        if (smith.value(bool)) _ = isis.pdu.stampLspChecksum(input) catch {};
    }

    // Both sides of the gate: `null` is a local origination (checksum exempt),
    // an interface index is a receive (checksum enforced).
    const arrival: ?u8 = if (smith.value(bool)) null else smith.valueRangeAtMost(u8, 0, 1);

    const before = db.count();
    if (db.insert(input, arrival, 1)) |_| {
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
    _ = @import("goldens.zig");
}
